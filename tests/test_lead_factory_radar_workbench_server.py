from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
import json
from threading import Thread

import pytest

from lead_factory.cli import main
from lead_factory.radar_workbench_demo import seed_demo_workspace
from lead_factory.radar_workbench_server import create_radar_workbench_server
from lead_factory.store import FactoryStore
from tests.test_lead_factory_schema_v14 import _create_exact_v13


@pytest.fixture
def browser_workspace(tmp_path):
    store = seed_demo_workspace(tmp_path / "demo.sqlite3")
    server = create_radar_workbench_server(store, actor="manager-1", port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(path, body=None, *, headers=None):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        actual_headers = {"Content-Type": "application/json", **(headers or {})}
        connection.request("POST" if body is not None else "GET", path,
                           json.dumps(body) if body is not None else None, actual_headers)
        response = connection.getresponse()
        payload = response.read()
        result = json.loads(payload) if "application/json" in response.getheader("Content-Type", "") else payload
        status, response_headers = response.status, dict(response.getheaders())
        connection.close()
        return status, result, response_headers

    yield store, request
    server.shutdown()
    server.server_close()
    thread.join(5)


def test_browser_flow_persists_human_report_without_external_effects(browser_workspace):
    store, request = browser_workspace
    status, session, _ = request("/api/session")
    assert status == 200 and session["demo"] is True
    assert session["actor"] == "manager-1"
    _, objects, _ = request("/api/objects")
    object_id = objects["items"][0]["object_id"]
    path = f"/api/objects/{object_id}"
    headers = {"X-Workspace-Token": session["token"]}
    due = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    assign = {"assignee": "manager-1", "due_at_utc": due, "expected_version": 0,
              "idempotency_key": "browser-assign", "actor": "forged-browser-actor"}
    assert request(path + "/assign", assign, headers=headers)[0] == 200
    result = {"result": "RFQ_REPORTED", "reason": "Уточнить размеры для расчёта",
              "next_action": "PREPARE_QUOTE", "next_action_at_utc": due,
              "evidence_ref": "evidence://radar-workbench/manager-note/browser-result",
              "expected_version": 1, "idempotency_key": "browser-result"}
    status, saved, _ = request(path + "/result", result, headers=headers)
    assert status == 200 and saved["reported_by"] == "manager-1"
    assert saved["verification"] == "HUMAN_REPORT_UNVERIFIED"
    assert request(path + "/result", result, headers=headers)[1] == saved
    stale = {**result, "idempotency_key": "stale-browser-result"}
    assert request(path + "/result", stale, headers=headers)[0] == 409
    _, dossier, _ = request(path)
    assert dossier["work_item"]["version"] == 2 and len(dossier["history"]) == 2
    with store.connect() as con:
        for table in ("opportunities", "crm_outbox", "outbox"):
            assert con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_cross_origin_and_unauthenticated_requests_cannot_read_or_write(browser_workspace):
    _, request = browser_workspace
    _, session, _ = request("/api/session")
    assert request("/api/session", headers={"Host": "evil.example"})[0] == 403
    assert request("/api/session", headers={"Origin": "https://evil.example"})[0] == 403
    assert request("/api/session", headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert request("/api/objects/any/assign", {})[0] == 403
    assert request("/api/objects/any/assign", {}, headers={"X-Workspace-Token": session["token"], "Origin": "https://evil.example"})[0] == 403
    assert request("/api/objects/any/assign", {"reason": "x" * 17000}, headers={"X-Workspace-Token": session["token"]})[0] == 413


def test_local_assets_have_browser_security_headers_and_no_path_access(browser_workspace):
    _, request = browser_workspace
    for path in ("/", "/workspace.js", "/workspace.css"):
        status, body, headers = request(path)
        assert status == 200 and body
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
        assert headers["Cache-Control"] == "no-store"
    assert request("/../lead_factory/store.py")[0] == 404
    assert request("/api/objects?limit=201")[0] == 400


def test_cli_requires_explicit_database_and_valid_actor_before_demo_creation(tmp_path):
    with pytest.raises(SystemExit):
        main(["serve-radar", "--actor", "manager-1"])
    path = tmp_path / "must-not-exist.sqlite3"
    with pytest.raises(SystemExit):
        main(["serve-radar", "--workspace-db", str(path), "--actor", "invalid actor", "--demo"])
    assert not path.exists()
    with pytest.raises(SystemExit):
        main(["import-radar", "--workspace-db", str(path), "--actor", "manager-1",
              "--passport", "missing", "--file", "missing.json"])
    assert not path.exists()


def test_startup_rejects_old_schema_before_binding_without_migration(tmp_path):
    path = tmp_path / "schema14.sqlite3"
    _create_exact_v13(path)
    store = FactoryStore(path)
    store.migrate_schema(target_version=14, actor="offline-test",
                         evidence_ref="test:workspace-v14", legacy_mailbox_mapping={})
    with pytest.raises(ValueError, match="schema 15"):
        create_radar_workbench_server(store, actor="manager-1", port=0)
    assert store.schema_version() == 14
