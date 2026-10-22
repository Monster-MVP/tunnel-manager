import json
import time

import pytest
from app.api.routes import create_router
from app.api.security import SecurityManager, SecurityMiddleware
from app.db.repository import Repository
from app.schemas.inputs import ServerInput
from fastapi import FastAPI
from fastapi.testclient import TestClient


def make_server(client, **values):
    response = client.post("/api/v1/servers", json={"name": "Test", "host": "example.test", "user": "tester", **values})
    assert response.status_code == 201, response.text
    return response.json()


def test_unauthenticated_reads_and_csrf_mutations_are_rejected(api):
    client, security = api
    assert client.get("/api/v1/servers").status_code == 401
    ticket = security.issue_bootstrap_ticket()
    response = client.post("/api/v1/sessions/exchange", json={"ticket": ticket})
    assert response.status_code == 200
    assert "httponly" in response.headers["set-cookie"].lower()
    assert client.post("/api/v1/sessions/exchange", json={"ticket": ticket}).status_code == 401
    assert client.post("/api/v1/servers", json={}).status_code == 401
    assert client.get("/api/v1/servers", headers={"Host": "evil.test"}).status_code == 403
    assert client.get("/api/v1/servers", headers={"Origin": "https://evil.test"}).status_code == 403


def test_crud_revision_and_groups(authed):
    group = authed.post("/api/v1/groups", json={"name": "Research"}).json()
    value = make_server(authed, group_id=group["id"])
    assert value["desired_state"] == "STOPPED"
    assert authed.patch(f"/api/v1/servers/{value['id']}", json={"name": "changed"}).status_code == 428
    changed = authed.patch(f"/api/v1/servers/{value['id']}", json={"name": "changed"}, headers={"If-Match": "1"})
    assert changed.status_code == 200 and changed.json()["revision"] == 2
    stale = authed.patch(f"/api/v1/servers/{value['id']}", json={"name": "stale"}, headers={"If-Match": "1"})
    assert stale.status_code == 409 and stale.json()["code"] == "REVISION_CONFLICT"
    assert authed.delete(f"/api/v1/groups/{group['id']}").status_code == 200
    assert authed.get(f"/api/v1/servers/{value['id']}").json()["group_id"] is None


@pytest.mark.parametrize("host", ["-oProxyCommand=bad", "hello world", "host;touch", "$(whoami)"])
def test_ssh_injection_input_rejected(authed, host):
    response = authed.post("/api/v1/servers", json={"name": "x", "host": host, "user": "u"})
    assert response.status_code == 422


def test_external_controls_and_migration_execute_blocked(authed):
    value = make_server(authed, management="OBSERVED_EXTERNAL")
    assert authed.post(f"/api/v1/servers/{value['id']}/actions/start").status_code == 403
    assert authed.post(f"/api/v1/servers/{value['id']}/actions/stop").status_code == 403
    assert authed.post(f"/api/v1/servers/{value['id']}/probes").status_code == 403
    proposal = authed.post("/api/v1/migrations/proposals", json={"server_id": value["id"]})
    assert proposal.json()["state"] == "PREVIEW_ONLY"
    assert authed.post(f"/api/v1/migrations/{proposal.json()['proposal_id']}/execute").status_code == 403


def test_settings_patch_does_not_reset_unrelated_fields(authed):
    assert authed.patch("/api/v1/settings", json={"theme": "dark"}).status_code == 200
    assert authed.patch("/api/v1/settings", json={"retry_base_s": 20}).status_code == 200
    assert authed.get("/api/v1/settings").json()["theme"] == "dark"
    assert authed.patch("/api/v1/settings", json={"arbitrary_path": "/usr/bin/evil"}).status_code == 422


def test_ssh_preview_never_evaluates_match_and_uses_first_value(authed, data_dir):
    content = """Host test
  HostName example.test
  User alice
  User bob
  Port 2222
Match exec \"touch SHOULD_NOT_EXIST\"
  HostName evil.test
  User evil
"""
    response = authed.post("/api/v1/imports/ssh-config/preview", json={"content": content})
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["candidates"]) == 1
    assert payload["candidates"][0]["host"] == "example.test" and payload["candidates"][0]["user"] == "alice"
    committed = authed.post(f"/api/v1/imports/{payload['preview_id']}/commit", json={"indexes": [0], "expected_hash": payload["source_sha256"]})
    assert committed.status_code == 200 and committed.json()["started"] is False
    disallowed = data_dir / "id_ed25519"
    disallowed.write_text("THIS BODY MUST NOT BE READ", encoding="utf-8")
    assert authed.post("/api/v1/imports/ssh-config/preview", json={"path": str(disallowed)}).status_code == 422


def test_configuration_roundtrip_and_authenticated_artifacts(authed):
    group = authed.post("/api/v1/groups", json={"name": "roundtrip"}).json()
    make_server(authed, group_id=group["id"])
    exported = authed.post("/api/v1/configuration/export", json={"include_connection_details": True}).json()
    content = authed.get(exported["download_url"])
    assert content.status_code == 200
    payload = json.loads(content.content)
    preview = authed.post("/api/v1/configuration/import/preview", json=payload)
    assert preview.status_code == 200, preview.text
    committed = authed.post(f"/api/v1/configuration/import/{preview.json()['preview_id']}/commit")
    assert committed.status_code == 200 and committed.json()["started"] is False
    servers = authed.get("/api/v1/servers").json()
    assert len(servers) == 2 and all(item["group_id"] == group["id"] for item in servers)
    authed.cookies.clear()
    assert authed.get(exported["download_url"]).status_code == 401


def test_websocket_ticket_once_only(api):
    _, security = api
    session = security.exchange(security.issue_bootstrap_ticket())
    ticket = security.issue_ws_ticket(session)
    assert security.consume_ws_ticket(ticket, session)
    assert not security.consume_ws_ticket(ticket, session)


def test_private_key_text_and_invalid_health_url_are_rejected(authed):
    assert authed.post("/api/v1/imports/ssh-config/preview", json={"content": "-----BEGIN OPENSSH PRIVATE KEY-----"}).status_code == 422
    with pytest.raises(ValueError):
        ServerInput(name="x", host="x.test", user="u", health_url="https://token@x.test/")


def test_actions_are_queued_and_engine_failures_are_reported(data_dir):
    class FakeEngine:
        async def start(self, server_id):
            raise RuntimeError("isolated test failure")

        def snapshot(self, server_id):
            return {"server_id": server_id, "state": "FAILED", "reason_code": "TEST_FAILURE"}

    repository = Repository(data_dir)
    app = FastAPI()
    security = SecurityManager("http://127.0.0.1:18401")
    app.state.security = security
    app.add_middleware(SecurityMiddleware, security=security)
    app.include_router(create_router(repository, FakeEngine()))
    with TestClient(app, base_url="http://127.0.0.1:18401") as client:
        exchange = client.post("/api/v1/sessions/exchange", json={"ticket": security.issue_bootstrap_ticket()})
        client.headers.update({"Origin": security.origin, "X-CSRF-Token": exchange.json()["csrf"]})
        value = make_server(client)
        queued = client.post(f"/api/v1/servers/{value['id']}/actions/start", headers={"Idempotency-Key": "start-1"})
        assert queued.status_code == 202
        operation_id = queued.json()["operation_id"]
        for _ in range(30):
            operation = client.get(f"/api/v1/operations/{operation_id}").json()
            if operation["status"] == "FAILED":
                break
            time.sleep(0.01)
        assert operation["status"] == "FAILED"
        duplicate = client.post(f"/api/v1/servers/{value['id']}/actions/start", headers={"Idempotency-Key": "start-1"})
        assert duplicate.status_code == 202 and duplicate.json()["operation_id"] == operation_id
    repository.close()
