from __future__ import annotations

import asyncio
import json
import sqlite3
import time

import httpx
import pytest
import websockets
from app.db.repository import Repository


def create_server(client, **fields):
    response = client.post("/api/v1/servers", json={"name": "QA isolated", "host": "127.0.0.1", "user": "qa",
                                                  "mode": "DISABLED", "auto_reconnect": False, **fields})
    assert response.status_code == 201, response.text
    return response.json()


def wait_operation(client, operation_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/operations/{operation_id}")
        assert response.status_code == 200
        operation = response.json()
        if operation["status"] in {"FAILED", "SUCCEEDED"}:
            return operation
        time.sleep(.03)
    pytest.fail(f"Operation never finished: {operation}")


def test_live_crud_modes_filters_revision_and_idempotency(live):
    client = live.client
    group = client.post("/api/v1/groups", json={"name": "QA group"}).json()
    server = create_server(client, group_id=group["id"])
    assert client.get("/api/v1/servers", params={"q": "isolated", "group": group["id"], "state": "STOPPED"}).json()[0]["id"] == server["id"]
    assert client.get("/api/v1/servers", params={"q": "absent"}).json() == []
    patched = client.patch(f"/api/v1/servers/{server['id']}", json={"name": "QA edited"}, headers={"If-Match": "1"})
    assert patched.status_code == 200
    assert client.patch(f"/api/v1/servers/{server['id']}", json={"name": "stale"}, headers={"If-Match": "1"}).status_code == 409
    assert client.put(f"/api/v1/servers/{server['id']}/mode", json={"mode": "DISABLED"}).status_code == 428
    mode = client.put(f"/api/v1/servers/{server['id']}/mode", json={"mode": "DISABLED"}, headers={"If-Match": str(patched.json()["revision"])})
    assert mode.status_code == 202
    assert wait_operation(client, mode.json()["operation_id"])["status"] == "SUCCEEDED"
    path = f"/api/v1/servers/{server['id']}/actions/start"
    first = client.post(path, headers={"Idempotency-Key": "qa-repeat"}).json()
    second = client.post(path, headers={"Idempotency-Key": "qa-repeat"}).json()
    assert first["operation_id"] == second["operation_id"]
    assert wait_operation(client, first["operation_id"])["status"] == "SUCCEEDED"
    assert client.get(f"/api/v1/servers/{server['id']}/runtime").json()["state"] == "STOPPED"
    assert client.delete(f"/api/v1/groups/{group['id']}").status_code == 200
    assert client.get(f"/api/v1/servers/{server['id']}").json()["group_id"] is None
    assert client.delete(f"/api/v1/servers/{server['id']}").status_code == 200
    assert client.get(f"/api/v1/servers/{server['id']}").status_code == 404


def test_live_import_export_settings_and_artifacts(live):
    client = live.client
    preview = client.post("/api/v1/imports/ssh-config/preview", json={"content": "Host qa-import\n HostName example.test\n User qa\n Port 2201\n"})
    assert preview.status_code == 200
    value = preview.json()
    imported = client.post(f"/api/v1/imports/{value['preview_id']}/commit", json={"indexes": [0], "expected_hash": value["source_sha256"]})
    assert imported.status_code == 200 and imported.json()["started"] is False
    assert client.post(f"/api/v1/imports/{value['preview_id']}/commit", json={"indexes": [0]}).status_code == 404
    client.patch("/api/v1/settings", json={"theme": "light"})
    client.patch("/api/v1/settings", json={"retry_base_s": 2})
    assert client.get("/api/v1/settings").json()["theme"] == "light"
    artifact = client.post("/api/v1/configuration/export", json={"include_connection_details": True}).json()
    exported = client.get(artifact["download_url"])
    assert exported.status_code == 200
    payload = exported.json()
    restored = client.post("/api/v1/configuration/import/preview", json=payload).json()
    committed = client.post(f"/api/v1/configuration/import/{restored['preview_id']}/commit")
    assert committed.status_code == 200 and committed.json()["started"] is False
    assert len(client.get("/api/v1/servers").json()) == 2
    diagnostics = client.post("/api/v1/diagnostics/exports").json()
    assert client.get(diagnostics["download_url"]).json()["schema_version"] == 1
    assert client.get("/api/v1/audit-events").json()


@pytest.mark.asyncio
async def test_live_websocket_updates_and_reconnect_snapshot(live):
    ticket = live.client.post("/api/v1/ws-tickets").json()["ticket"]
    url = live.origin.replace("http://", "ws://") + "/api/v1/ws"
    cookie = "; ".join(f"{name}={value}" for name, value in live.client.cookies.items())
    async with websockets.connect(url, origin=live.origin, additional_headers={"Cookie": cookie}, proxy=None) as websocket:
        await websocket.send(json.dumps({"type": "authenticate", "ticket": ticket}))
        assert json.loads(await websocket.recv())["type"] == "snapshot"
        async with httpx.AsyncClient(base_url=live.origin, cookies=live.client.cookies, headers=dict(live.client.headers), trust_env=False) as client:
            created = await client.post("/api/v1/servers", json={"name": "WS isolated", "host": "127.0.0.1", "user": "qa", "mode": "DISABLED"})
        event = json.loads(await asyncio.wait_for(websocket.recv(), 2))
        assert event["type"] == "server.created"
        assert event["server_id"] == created.json()["id"]
    replacement = live.client.post("/api/v1/ws-tickets").json()["ticket"]
    async with websockets.connect(url, origin=live.origin, additional_headers={"Cookie": cookie}, proxy=None) as websocket:
        await websocket.send(json.dumps({"type": "authenticate", "ticket": replacement}))
        snapshot = json.loads(await websocket.recv())
        assert snapshot["payload"]["servers"][0]["id"] == created.json()["id"]


def test_storage_busy_returns_failure_and_preserves_configuration(live):
    blocker = sqlite3.connect(live.data_dir / "tunnel-manager.sqlite3", timeout=.1)
    blocker.execute("BEGIN IMMEDIATE")
    start = time.monotonic()
    try:
        response = live.client.post("/api/v1/groups", json={"name": "must-not-be-saved"})
    finally:
        blocker.rollback()
        blocker.close()
    assert response.status_code == 503 and response.json()["code"] == "STORAGE_UNAVAILABLE"
    assert time.monotonic() - start < 7
    assert live.client.get("/api/v1/groups").json() == []
    assert live.client.get("/healthz").json()["alive"] is True


def test_reopen_does_not_report_stale_pid_as_healthy(project_data_dir, backend_factory):
    data_dir = project_data_dir / "reopen"
    repo = Repository(data_dir)
    server = repo.create_server({"name": "historical", "host": "127.0.0.1", "user": "qa", "mode": "DISABLED"})
    repo.save_runtime({"server_id": server["id"], "state": "HEALTHY", "stale": False,
                       "process_alive": True, "ssh_connected": True, "pid": 987654})
    repo.close()
    live = backend_factory(data_dir)
    try:
        runtime = live.client.get(f"/api/v1/servers/{server['id']}/runtime").json()
        assert runtime["state"] != "HEALTHY", runtime
        assert runtime["process_alive"] is False and runtime["ssh_connected"] is False
    finally:
        live.close()


def test_reopen_resolves_interrupted_operation(project_data_dir, backend_factory):
    data_dir = project_data_dir / "operations"
    repo = Repository(data_dir)
    server = repo.create_server({"name": "historical", "host": "127.0.0.1", "user": "qa", "mode": "DISABLED"})
    operation, _ = repo.create_operation(server["id"], "start", "qa", None, {})
    repo.update_operation(operation["id"], "RUNNING")
    repo.close()
    live = backend_factory(data_dir)
    try:
        value = live.client.get(f"/api/v1/operations/{operation['id']}").json()
        assert value["status"] == "FAILED", value
        assert value["error_code"] == "BACKEND_INTERRUPTED", value
    finally:
        live.close()
