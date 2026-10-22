import json
import time

import pytest
from app.api.security import SecurityManager
from starlette.websockets import WebSocketDisconnect


def create_profile(client, **overrides):
    response = client.post("/api/v1/servers", json={
        "name": "Security isolated profile", "host": "private-host.example.test", "user": "private-user",
        **overrides,
    })
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.parametrize("origin,host", [
    ("https://attacker.example", "127.0.0.1:18401"),
    ("null", "127.0.0.1:18401"),
    ("http://127.0.0.1:18401.attacker.example", "127.0.0.1:18401"),
    ("http://127.0.0.1:18401", "attacker.example"),
    ("http://127.0.0.1:18401", "localhost:18401"),
])
def test_cross_origin_and_rebinding_rejected(authenticated_api, origin, host):
    client, app = authenticated_api
    response = client.post("/api/v1/groups", json={"name": "attack"}, headers={"Origin": origin, "Host": host})
    assert response.status_code == 403
    assert app.state.repo.list_groups() == []


def test_missing_csrf_rejected_with_valid_cookie(authenticated_api):
    client, _ = authenticated_api
    del client.headers["x-csrf-token"]
    assert client.post("/api/v1/groups", json={"name": "attack"}).status_code == 401


def test_non_ascii_csrf_is_rejected_without_server_error(authenticated_api):
    client, _ = authenticated_api
    response = client.post("/api/v1/groups", json={"name": "attack"}, headers={"X-CSRF-Token": b"\xe9" * 32})
    assert response.status_code == 401


def test_bootstrap_and_ws_tickets_expire_and_are_single_use():
    security = SecurityManager()
    expired = security.issue_bootstrap_ticket()
    security._bootstrap[expired] = time.time() - 1
    assert security.exchange(expired) is None
    ticket = security.issue_bootstrap_ticket()
    session = security.exchange(ticket)
    assert session is not None and security.exchange(ticket) is None
    websocket_ticket = security.issue_ws_ticket(session)
    security._ws_tickets[websocket_ticket] = (session.token, time.time() - 1)
    assert not security.consume_ws_ticket(websocket_ticket, session)


def test_websocket_ticket_capacity_returns_429_without_secret(authenticated_api):
    client, _ = authenticated_api
    for _ in range(128):
        assert client.post("/api/v1/ws-tickets").status_code == 200
    limited = client.post("/api/v1/ws-tickets")
    assert limited.status_code == 429
    assert "ticket" not in limited.json()


def test_websocket_rejects_foreign_origin_and_invalid_first_frame(authenticated_api):
    client, app = authenticated_api
    with pytest.raises(WebSocketDisconnect), client.websocket_connect(
        "/api/v1/ws", headers={"Origin": "https://attacker.example"}
    ):
        pass
    with client.websocket_connect("/api/v1/ws", headers={"Origin": app.state.security.origin,
                                                       "Host": "127.0.0.1:18401",
                                                       "Cookie": f"tm_session={client.cookies.get('tm_session')}"}) as websocket:
        websocket.send_json({"type": "authenticate", "ticket": "invalid"})
        with pytest.raises(WebSocketDisconnect):
            websocket.receive_json()


def test_active_websocket_rejects_revoked_session(authenticated_api):
    client, app = authenticated_api
    session_token = client.cookies.get("tm_session")
    ticket = client.post("/api/v1/ws-tickets").json()["ticket"]
    with client.websocket_connect("/api/v1/ws", headers={
        "Origin": app.state.security.origin, "Host": "127.0.0.1:18401",
        "Cookie": f"tm_session={session_token}",
    }) as websocket:
        websocket.send_json({"type": "authenticate", "ticket": ticket})
        websocket.receive_json()
        app.state.security.revoke(session_token)
        websocket.send_json({"type": "ping"})
        with pytest.raises(WebSocketDisconnect):
            websocket.receive_json()


@pytest.mark.parametrize("invalid", [[], None, {"type": []}, {"type": {"nested": "invalid"}}, {"type": "unknown"}])
def test_active_websocket_invalid_message_is_closed(authenticated_api, invalid):
    client, app = authenticated_api
    ticket = client.post("/api/v1/ws-tickets").json()["ticket"]
    with client.websocket_connect("/api/v1/ws", headers={
        "Origin": app.state.security.origin, "Host": "127.0.0.1:18401",
        "Cookie": f"tm_session={client.cookies.get('tm_session')}",
    }) as websocket:
        websocket.send_json({"type": "authenticate", "ticket": ticket})
        websocket.receive_json()
        websocket.send_json(invalid)
        with pytest.raises(WebSocketDisconnect):
            websocket.receive_json()


def test_external_controls_and_production_takeover_always_rejected(authenticated_api):
    client, _ = authenticated_api
    profile = create_profile(client, management="OBSERVED_EXTERNAL")
    for action in ("start", "stop", "restart"):
        assert client.post(f"/api/v1/servers/{profile['id']}/actions/{action}").status_code == 403
    assert client.put(f"/api/v1/servers/{profile['id']}/mode", json={"mode": "DISABLED"},
                      headers={"If-Match": "1"}).status_code == 403
    assert client.post("/api/v1/migrations/any-proposal/execute").status_code == 403


@pytest.mark.parametrize("field,value", [
    ("host", "-oProxyCommand=evil"), ("host", "x; touch forbidden"),
    ("user", "$(id)"), ("ssh_alias", "alias\nMatch exec evil"),
    ("identity_file_ref", "/keys/../secret"), ("identity_file_ref", "/keys/%h"),
    ("health_url", "https://user:SYNTHETIC-CREDENTIAL@example.test/"),
    ("health_url", "https://example.test/?api_key=SYNTHETIC-CREDENTIAL"),
])
def test_shell_and_path_injection_not_persisted(authenticated_api, field, value):
    client, app = authenticated_api
    response = client.post("/api/v1/servers", json={"name": "attack", "host": "example.test", "user": "tester",
                                                       field: value})
    assert response.status_code == 422
    assert app.state.repo.list_servers() == []
    assert "SYNTHETIC-CREDENTIAL" not in response.text


def test_import_does_not_evaluate_arbitrary_shell(authenticated_api, tmp_path):
    client, app = authenticated_api
    marker = tmp_path / "must-not-exist"
    content = (f'Host isolated\nHostName example.test\nUser tester\n'
               f'Match exec "touch {marker}"\nProxyCommand touch {marker}\n'
               f'Include {tmp_path / "never-read"}\n')
    response = client.post("/api/v1/imports/ssh-config/preview", json={"content": content})
    assert response.status_code == 200
    assert not marker.exists()
    assert app.state.repo.list_servers() == []


def test_ssh_import_rejects_symlink_ancestor_before_read(authenticated_api, tmp_path, monkeypatch):
    client, _ = authenticated_api
    sandbox = tmp_path / "import-cwd"
    sandbox.mkdir()
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    (unrelated / "config").write_text("Host sentinel\nHostName sentinel.example.test\nUser tester\n")
    (sandbox / ".ssh").symlink_to(unrelated, target_is_directory=True)
    monkeypatch.chdir(sandbox)
    response = client.post("/api/v1/imports/ssh-config/preview", json={"path": str(sandbox / ".ssh" / "config")})
    assert response.status_code == 422
    assert "sentinel.example.test" not in response.text


def test_ssh_import_commit_rechecks_symlink_ancestors(authenticated_api, tmp_path, monkeypatch):
    client, _ = authenticated_api
    sandbox = tmp_path / "commit-cwd"
    sandbox.mkdir()
    original = sandbox / ".ssh"
    original.mkdir()
    content = "Host sentinel\nHostName sentinel.example.test\nUser tester\n"
    (original / "config").write_text(content)
    monkeypatch.chdir(sandbox)
    response = client.post("/api/v1/imports/ssh-config/preview", json={"path": str(original / "config")})
    assert response.status_code == 200
    preview = response.json()
    original.rename(sandbox / "ssh-before-swap")
    unrelated = tmp_path / "unrelated-commit"
    unrelated.mkdir()
    (unrelated / "config").write_text(content)
    original.symlink_to(unrelated, target_is_directory=True)
    committed = client.post(f"/api/v1/imports/{preview['preview_id']}/commit", json={"indexes": [0]})
    assert committed.status_code == 409


def test_default_export_redacts_all_connection_metadata(authenticated_api):
    client, _ = authenticated_api
    create_profile(client, ssh_alias="private-alias", health_url="https://private-probe.example.test/account-private/")
    response = client.post("/api/v1/configuration/export", json={})
    assert response.status_code == 200
    payload = client.get(response.json()["download_url"])
    assert payload.status_code == 200
    content = json.dumps(payload.json())
    for private in ("private-host", "private-user", "private-alias", "private-probe", "account-private"):
        assert private not in content


@pytest.mark.parametrize("endpoint", ["/configuration/export", "/diagnostics/exports"])
def test_shareable_artifact_redacts_connection_metadata_in_display_names(authenticated_api, endpoint):
    client, _ = authenticated_api
    create_profile(client, name="private-host.example.test private-user private-alias", ssh_alias="private-alias")
    exported = client.post("/api/v1" + endpoint, json={} if endpoint == "/configuration/export" else None)
    assert exported.status_code == 200
    artifact = client.get(exported.json()["download_url"])
    assert artifact.status_code == 200
    for sensitive in ("private-host.example.test", "private-user", "private-alias"):
        assert sensitive not in artifact.text


def test_artifact_symlink_and_traversal_fail_closed(authenticated_api, tmp_path):
    client, app = authenticated_api
    artifact = client.post("/api/v1/diagnostics/exports").json()
    target = app.state.repo.get_artifact(artifact["artifact_id"])
    target.unlink()
    unrelated = tmp_path / "sensitive-fixture.json"
    unrelated.write_text('{"do_not_export":"synthetic-sentinel"}')
    target.symlink_to(unrelated)
    response = client.get(artifact["download_url"])
    assert response.status_code == 503
    assert "synthetic-sentinel" not in response.text
    assert client.get("/api/v1/artifacts/../../sensitive-fixture.json").status_code in {400, 404}
