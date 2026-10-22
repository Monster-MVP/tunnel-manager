import asyncio
import json
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from app.api import discovery, routes
from app.schemas.inputs import DiagnosticsInput


def profile(client, **values):
    response = client.post("/api/v1/servers", json={"name": "isolated security", "host": "fixture.test", "user": "fixture", **values})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.parametrize("path", ["/discovery", "/activity", "/servers/00000000-0000-0000-0000-000000000000/metrics/history?range=7d"])
def test_new_read_capabilities_require_session(secured_api, path):
    client, _ = secured_api
    response = client.get("/api/v1" + path)
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path,body", [("/preflight", {}), ("/tests", {"kind": "proxy"}), ("/diagnostics", {}), ("/discovery/import", {"indexes": [0], "discovery_id": "invalid"})])
def test_new_post_capabilities_require_csrf_without_mutation(secured_session, path, body):
    client, app = secured_session
    server = profile(client, mode="DISABLED")
    target = "/api/v1" + path if path.startswith("/discovery") else f"/api/v1/servers/{server['id']}" + path
    before = app.state.repo.get_server(server["id"])
    del client.headers["x-csrf-token"]
    response = client.post(target, json=body)
    assert response.status_code == 401
    assert app.state.repo.get_server(server["id"]) == before
    assert not app.state.engine._runs


@pytest.mark.parametrize("path", ["/discovery", "/activity"])
def test_new_read_capabilities_reject_foreign_origin_and_host(secured_session, path):
    client, _ = secured_session
    for headers in ({"Origin": "https://attacker.test"}, {"Host": "127.0.0.1:18401.attacker.test"}):
        assert client.get("/api/v1" + path, headers=headers).status_code == 403


@pytest.mark.parametrize("url", [
    "https://hubway.cc.evil.test/v1", "https://hubway.cc@evil.test/v1", "https://evil.test@hubway.cc/v1",
    "https://hubway.cc/v1?api_key=SYNTHETIC-KEY", "https://hubway.cc/v1#SYNTHETIC-KEY", "https://hubway.cc/v1/completions",
    "https://hubway.cc:8443/v1", "http://hubway.cc/v1", "https://127.0.0.1/v1", "https://hubway.cc/%76%31",
    "https://hubway.cc/v1\nX-Api-Key: SYNTHETIC-KEY",
])
def test_diagnostics_cannot_expand_target_or_accept_secrets(url):
    with pytest.raises(ValueError):
        DiagnosticsInput(target_url=url)


@pytest.mark.parametrize("authority", ["hubway.cc:{sentinel}", "[{sentinel}]", "hubway.cc\uff1a{sentinel}"])
def test_diagnostic_malformed_port_error_does_not_echo_supplied_credential(secured_session, authority):
    client, _ = secured_session
    server = profile(client, mode="DISABLED")
    sentinel = "SYNTHETIC-KEY-NOT-A-REAL-CREDENTIAL"
    url = "https://" + authority.format(sentinel=sentinel) + "/v1"
    response = client.post(f"/api/v1/servers/{server['id']}/diagnostics", json={"target_url": url})
    assert response.status_code == 422
    assert sentinel not in response.text


@pytest.mark.parametrize("authority", ["[{sentinel}]", "example.test\uff1a{sentinel}"])
def test_health_url_parse_errors_never_echo_supplied_secret(secured_session, authority):
    client, app = secured_session
    sentinel = "SYNTHETIC-KEY-NOT-A-REAL-CREDENTIAL"
    url = "https://" + authority.format(sentinel=sentinel) + "/"
    response = client.post("/api/v1/servers", json={"name": "invalid url", "host": "fixture.test", "user": "fixture", "health_url": url})
    assert response.status_code == 422
    assert sentinel not in response.text
    assert app.state.repo.list_servers() == []


@pytest.mark.parametrize("field,value", [
    ("health_url", "https://fixture.test/?api_key=SYNTHETIC-KEY-NOT-A-REAL-CREDENTIAL"),
    ("identity_file_ref", "/fixture/../SYNTHETIC-KEY-NOT-A-REAL-CREDENTIAL"),
])
def test_profile_patch_validation_never_echoes_rejected_values(secured_session, field, value):
    client, app = secured_session
    server = profile(client, mode="DISABLED")
    response = client.patch(f"/api/v1/servers/{server['id']}", json={field: value}, headers={"If-Match": str(server["revision"])})
    assert "SYNTHETIC-KEY-NOT-A-REAL-CREDENTIAL" not in response.text, response.text
    assert response.status_code == 422
    assert app.state.repo.get_server(server["id"]) == server


def test_external_import_and_all_controls_remain_observe_only(secured_session, monkeypatch):
    client, app = secured_session
    async def collect(_):
        return {"ssh_config": {"candidates": [{"ssh_alias": "discovered", "host": "example.test", "user": "fixture", "ssh_port": 2222,
                "remote_proxy_port": 17890, "proxy_port": 7890, "management": "OBSERVED_EXTERNAL", "health": "UNKNOWN"}]}}
    monkeypatch.setattr(routes, "collect_discovery", collect)
    snapshot = client.get("/api/v1/discovery")
    assert snapshot.status_code == 200
    result = client.post("/api/v1/discovery/import", json={"indexes": [0], "discovery_id": snapshot.json()["discovery_id"]})
    assert result.status_code == 201 and result.json()["started"] is False
    server = result.json()["servers"][0]
    assert server["management"] == "OBSERVED_EXTERNAL" and server["desired_state"] == "STOPPED" and server["mode"] == "DISABLED"
    for action in ("start", "stop", "restart"):
        assert client.post(f"/api/v1/servers/{server['id']}/actions/{action}").status_code == 403
    for endpoint, body in (("/tests", {"kind": "connection"}), ("/diagnostics", {}), ("/probes", {})):
        assert client.post(f"/api/v1/servers/{server['id']}" + endpoint, json=body).status_code == 403
    assert client.put(f"/api/v1/servers/{server['id']}/mode", json={"mode": "MAC_DIRECT"}, headers={"If-Match": str(server["revision"])}).status_code == 403
    assert client.patch(f"/api/v1/servers/{server['id']}", json={"management": "MANAGED"}, headers={"If-Match": str(server["revision"])}).status_code == 422
    proposal = client.post("/api/v1/migrations/proposals", json={"server_id": server["id"]}).json()
    assert proposal["execution_enabled"] is False
    assert client.post(f"/api/v1/migrations/{proposal['proposal_id']}/execute", json={}).status_code == 403
    assert not app.state.engine._runs and not app.state.engine.proxy.snapshot()["managed_tinyproxy"]


@pytest.mark.parametrize("indexes", [[-1], [1], [999], []])
def test_unknown_or_invalid_discovery_selection_does_not_save(secured_session, indexes):
    client, app = secured_session
    result = client.post("/api/v1/discovery/import", json={"indexes": indexes, "discovery_id": str(uuid4())})
    assert result.status_code in {409, 422}
    assert app.state.repo.list_servers() == []


@pytest.mark.parametrize("remote_port", [17890, 17891])
def test_wizard_cannot_start_protected_production_port(secured_session, remote_port):
    client, app = secured_session
    server = profile(client, remote_proxy_port=remote_port)
    before = app.state.repo.get_server(server["id"])
    response = client.post(f"/api/v1/servers/{server['id']}/tests", json={"kind": "proxy"})
    assert response.status_code == 409
    assert response.json()["code"] == "PROTECTED_PRODUCTION_PORT"
    assert app.state.repo.get_server(server["id"]) == before
    assert not app.state.engine._runs and not app.state.engine.proxy.snapshot()["managed_tinyproxy"]


def test_discovery_parser_never_evaluates_shell_or_reads_references(tmp_path):
    marker = tmp_path / "must-not-exist"
    config = tmp_path / "config"
    reference = tmp_path / "identity-reference-only"
    config.write_text(f'Host example\n HostName example.test\n User fixture\n IdentityFile {reference}\n ProxyCommand touch {marker}\n Include {tmp_path / "missing"}\n Match exec "touch {marker}"\n HostName secret.test\n User secret\n', encoding="utf-8")
    candidates, warnings, state, _ = discovery._parse_ssh(config)
    assert state == "observed" and len(candidates) == 1
    assert candidates[0]["health"] == "UNKNOWN" and candidates[0]["management"] == "OBSERVED_EXTERNAL"
    assert candidates[0]["identity_file_ref"] == str(reference)
    assert not reference.exists() and not marker.exists()
    assert "secret.test" not in json.dumps(candidates)
    assert any("Match" in item for item in warnings)


def test_discovery_parent_symlink_is_uninspected_and_oversize_is_bounded(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    config = actual / "config"
    config.write_text("Host safe\n HostName fixture.test\n User fixture\n")
    link = tmp_path / "alias"
    link.symlink_to(actual, target_is_directory=True)
    assert discovery._parse_ssh(link / "config")[2] == "uninspected"
    config.write_text("SYNTHETIC-OVERSIZED-DATA" * 60000)
    candidates, warnings, state, digest = discovery._parse_ssh(config)
    assert candidates == [] and state == "inaccessible" and digest is None
    assert "SYNTHETIC-OVERSIZED-DATA" not in json.dumps(warnings)


async def test_discovery_subprocess_output_and_timeout_are_bounded():
    output, error = await discovery._command([str(Path(sys.executable).resolve()), "-c", "import sys; sys.stdout.write('x'*1200000)"])
    assert len(output.encode()) == 1_048_576 and error == "OUTPUT_TRUNCATED"
    output, error = await discovery._command([str(Path(sys.executable).resolve()), "-c", "import time; time.sleep(2)"], timeout=0.05)
    assert output == "" and error == "不可访问"


async def test_discovery_subprocess_cancellation_reaps_only_its_child(monkeypatch):
    original = asyncio.create_subprocess_exec
    children = []
    async def tracked(*argv, **kwargs):
        child = await original(*argv, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(asyncio, "create_subprocess_exec", tracked)
    task = asyncio.create_task(discovery._command([str(Path(sys.executable).resolve()), "-c", "import time; time.sleep(10)"]))
    try:
        for _ in range(100):
            if children:
                break
            await asyncio.sleep(0.01)
        assert len(children) == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.02)
        assert children[0].returncode is not None, "Cancelled discovery left its owned status child alive"
    finally:
        if children and children[0].returncode is None:
            children[0].terminate()
            await children[0].wait()


async def test_discovery_cancellation_drains_real_paused_output_with_deadline(monkeypatch):
    """Exercise a full subprocess pipe; a kill + wait without draining hangs."""
    spawn = asyncio.create_subprocess_exec
    read = asyncio.StreamReader.read
    children = []
    held = False

    async def tracked(*argv, **kwargs):
        child = await spawn(*argv, **kwargs)
        children.append(child)
        return child

    async def stall_first_stdout(stream, size=-1):
        nonlocal held
        if children and stream is children[0].stdout and not held:
            held = True
            # Fault injection stalls only this child's consumer while its real
            # stdout pipe fills and StreamReader pauses the actual transport.
            await asyncio.Future()
        return await read(stream, size)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", tracked)
    monkeypatch.setattr(asyncio.StreamReader, "read", stall_first_stdout)
    task = asyncio.create_task(discovery._command([
        str(Path(sys.executable).resolve()), "-c",
        "import os,time;\nfor _ in range(1024): os.write(1,b'x'*65536)\ntime.sleep(10)",
    ], timeout=10))
    try:
        for _ in range(200):
            if children and children[0].stdout._paused:
                break
            await asyncio.sleep(0.005)
        assert len(children) == 1 and children[0].stdout._paused
        assert len(children[0].stdout._buffer) > 65536
        started = asyncio.get_running_loop().time()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1)
        assert asyncio.get_running_loop().time() - started < 1
        assert children[0].returncode is not None
    finally:
        if children and children[0].returncode is None:
            children[0].kill()
        if children:
            await asyncio.wait_for(children[0].communicate(), timeout=2)
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("trigger", ["cancel", "timeout"])
async def test_owned_probe_execution_drains_noisy_child_on_timeout_or_cancel(tmp_path, monkeypatch, trigger):
    from app.db.repository import Repository
    from app.tunnels.manager import TunnelManager

    spawn = asyncio.create_subprocess_exec
    read = asyncio.StreamReader.read
    children = []
    held = False

    async def tracked(*argv, **kwargs):
        child = await spawn(*argv, **kwargs)
        children.append(child)
        return child

    async def stall_first_stdout(stream, size=-1):
        nonlocal held
        if children and stream is children[0].stdout and not held:
            held = True
            await asyncio.Future()
        return await read(stream, size)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", tracked)
    monkeypatch.setattr(asyncio.StreamReader, "read", stall_first_stdout)
    repo = Repository(tmp_path / "data")
    engine = TunnelManager(tmp_path / "data", repo)
    task = asyncio.create_task(engine._execute([
        str(Path(sys.executable).resolve()), "-c",
        "import os,time;\nfor _ in range(1024): os.write(1,b'x'*65536)\ntime.sleep(10)",
    ], timeout=0.2 if trigger == "timeout" else 10))
    try:
        for _ in range(200):
            if children and children[0].stdout._paused:
                break
            await asyncio.sleep(0.005)
        assert len(children) == 1 and children[0].stdout._paused
        if trigger == "cancel":
            task.cancel()
        finished, _ = await asyncio.wait({task}, timeout=1)
        assert task in finished, "Owned probe cleanup hung on paused subprocess pipes"
        if trigger == "cancel":
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            assert await task == (124, b"", b"")
        assert children[0].returncode is not None
    finally:
        if children and children[0].returncode is None:
            children[0].kill()
        if children:
            await asyncio.wait_for(children[0].communicate(), timeout=2)
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await engine.close()
        repo.close()


async def test_owned_probe_rejects_actual_oversize_output_without_stalling(tmp_path, monkeypatch):
    from app.db.repository import Repository
    from app.tunnels.manager import TunnelManager

    spawn = asyncio.create_subprocess_exec
    children = []
    async def tracked(*argv, **kwargs):
        child = await spawn(*argv, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(asyncio, "create_subprocess_exec", tracked)
    repo = Repository(tmp_path / "data")
    engine = TunnelManager(tmp_path / "data", repo)
    task = asyncio.create_task(engine._execute([
        str(Path(sys.executable).resolve()), "-c",
        "import os,time;\nfor _ in range(1024): os.write(1,b'x'*65536)\ntime.sleep(10)",
    ], timeout=10))
    try:
        finished, _ = await asyncio.wait({task}, timeout=1)
        assert task in finished, "Actual oversized probe output hung instead of rejecting with bounded cleanup"
        assert await task == (124, b"", b"")
        assert len(children) == 1 and children[0].returncode is not None
    finally:
        if children and children[0].returncode is None:
            children[0].kill()
        if children:
            await asyncio.wait_for(children[0].communicate(), timeout=2)
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await engine.close()
        repo.close()
