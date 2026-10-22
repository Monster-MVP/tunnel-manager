"""Actual OpenSSH mux checks against an owned loopback server and synthetic auth files.

The SSH fixture runs the exact fixed remote helper in a child with isolated HOME
and CODEX_HOME. No personal credential file or production SSH target is read.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shlex
from pathlib import Path

import asyncssh
import httpx
import pytest
from app.monitoring.codex_credentials import SOURCE, build_remote_codex_command

from tests.integration.test_fault_recovery import action, free_port, runtime

SENTINEL = "SYNTHETIC-CODEX-LIVE-KEY-NEVER-A-REAL-CREDENTIAL"
CHECK_BODY = {"source": SOURCE, "consent": True}
ROOT = Path(__file__).resolve().parents[2]


def write_auth(directory: Path, document):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "auth.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    return path


@pytest.fixture
async def codex_network(live):
    connections = []
    home = live.data_dir.parent / "synthetic-remote-home"
    codex_home = live.data_dir.parent / "synthetic-codex-home"
    home.mkdir(mode=0o700)
    codex_home.mkdir(mode=0o700)
    state = {"use_codex_home": False, "reads": 0, "queries": [], "children": [],
             "stdout": None, "stderr": None, "exit": None}

    class Server(asyncssh.SSHServer):
        def connection_made(self, connection):
            connections.append(connection)

        def begin_auth(self, username):
            return False

        def server_requested(self, host, port):
            return host == "127.0.0.1" and port >= 1024

    async def command(process):
        state["queries"].append(process.command)
        if process.command == build_remote_codex_command():
            state["reads"] += 1
            if state["exit"] is not None:
                process.stdout.write(state["stdout"] or "")
                process.stderr.write(state["stderr"] or "")
                process.exit(state["exit"])
                return
            environment = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
            if state["use_codex_home"]:
                environment["CODEX_HOME"] = str(codex_home)
            # Exact constant command, owned synthetic environment, system shell.
            child = await asyncio.create_subprocess_exec("/bin/sh", "-c", process.command,
                cwd=ROOT, env=environment, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            state["children"].append(child)
            try:
                out, err = await asyncio.wait_for(child.communicate(), 4)
            except BaseException:
                if child.returncode is None:
                    child.kill()
                    await child.communicate()
                raise
            process.stdout.write(out.decode("ascii"))
            process.stderr.write(err.decode("ascii"))
            process.exit(child.returncode)
        elif process.command.startswith("if command -v ss"):
            port = int(re.search(r"sport = :(\d+)", process.command)[1])
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                await writer.wait_closed()
                process.exit(0)
            except OSError:
                process.exit(1)
        elif process.command.startswith("curl "):
            arguments = shlex.split(process.command)
            assert arguments[:2] == ["curl", "-q"]
            child = await asyncio.create_subprocess_exec("/usr/bin/curl", *arguments[1:],
                env={"PATH": "/usr/bin:/bin"}, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            state["children"].append(child)
            try:
                out, err = await asyncio.wait_for(child.communicate(), 5)
            except BaseException:
                if child.returncode is None:
                    child.kill()
                    await child.communicate()
                raise
            process.stdout.write(out.decode())
            process.stderr.write(err.decode())
            process.exit(child.returncode)
        else:
            process.exit(69)

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    ssh = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[host_key], server_factory=Server,
                                process_factory=command, encoding="utf-8")
    known = live.data_dir / "known_hosts"
    known.write_bytes(f"[127.0.0.1]:{ssh.get_port()} ".encode() + host_key.export_public_key())
    known.chmod(0o600)

    async def proxy_request(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    proxy = await asyncio.start_server(proxy_request, "127.0.0.1", 0)
    async with httpx.AsyncClient(base_url=live.origin, trust_env=False, cookies=live.client.cookies,
                                headers=dict(live.client.headers), timeout=15) as client:
        assert (await client.patch("/api/v1/settings", json={"health_interval_s": 3600,
            "connect_timeout_s": 3, "probe_timeout_s": 2})).status_code == 200
        created = await client.post("/api/v1/servers", json={"name": "isolated Codex live fixture", "host": "127.0.0.1",
            "ssh_port": ssh.get_port(), "user": "qa", "mode": "CLASH_HTTP", "auto_reconnect": False,
            "proxy_port": proxy.sockets[0].getsockname()[1], "remote_proxy_port": free_port(),
            "health_url": "http://fixture.invalid/health", "expected_status": [200]})
        assert created.status_code == 201
        try:
            yield live, client, created.json(), state, home, codex_home, connections
        finally:
            await action(client, created.json(), "stop")
            ssh.close()
            await ssh.wait_closed()
            for connection in connections:
                connection.close()
                await connection.wait_closed()
            proxy.close()
            await proxy.wait_closed()
            for child in state["children"]:
                if child.returncode is None:
                    child.kill()
                    await child.communicate()


async def credential_check(client, server, body=None):
    result = await client.post(f"/api/v1/servers/{server['id']}/credentials/codex/check",
                               json=CHECK_BODY if body is None else body)
    assert SENTINEL not in result.text
    assert result.status_code == 200, result.text
    document = result.json()
    assert document["authentication"] == document["model_completion"] == "NOT_TESTED"
    assert document["llm_completion_verified"] is False
    return document


def assert_no_persisted_secret(live):
    for path in live.data_dir.rglob("*"):
        if path.is_file():
            assert SENTINEL.encode() not in path.read_bytes(), path
    assert SENTINEL.encode() not in live.log_path.read_bytes()


async def test_actual_remote_helper_requires_click_then_reuses_current_owned_master(codex_network):
    live, client, server, state, home, codex_home, connections = codex_network
    auth = write_auth(home / ".codex", {"OPENAI_API_KEY": SENTINEL})
    stopped = await credential_check(client, server)
    assert stopped["credential_state"] == "CHECK_UNAVAILABLE" and stopped["key_readable"] is None
    assert not connections and state["reads"] == 0
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    initial = await runtime(client, server)
    assert initial["state"] == "HEALTHY" and len(connections) == 1
    assert state["reads"] == 0, "Starting a channel must not automatically read auth.json"
    denied = await client.post(f"/api/v1/servers/{server['id']}/credentials/codex/check",
                               json={"source": SOURCE, "consent": False})
    assert denied.status_code == 403 and state["reads"] == 0
    for path in ("/api/v1/overview", "/api/v1/activity", "/api/v1/settings",
                 f"/api/v1/servers/{server['id']}/runtime"):
        assert (await client.get(path)).status_code == 200
    assert state["reads"] == 0, "Rendering and status queries must not read credentials"
    result = await credential_check(client, server)
    assert result["credential_state"] == "READABLE" and result["key_readable"] is True
    assert result["source_location"] == "HOME_DEFAULT" and result["check_completed"]
    assert result["ssh_connected"] and state["reads"] == 1
    write_auth(codex_home, {"auth_mode": "chatgpt", "tokens": {"access_token": SENTINEL}})
    state["use_codex_home"] = True
    oauth = await credential_check(client, server)
    assert oauth["credential_state"] == "OAUTH_ONLY" and oauth["key_readable"] is False
    assert oauth["source_location"] == "CODEX_HOME" and oauth["auth_mode"] == "OAUTH"
    (codex_home / "auth.json").unlink()
    missing = await credential_check(client, server)
    assert missing["credential_state"] == "NOT_FOUND" and missing["key_readable"] is False
    assert state["reads"] == 3 and len(connections) == 1
    current = await runtime(client, server)
    assert current["pid"] == initial["pid"] and current["state"] == "HEALTHY"
    assert (await client.get(f"/api/v1/servers/{server['id']}")).json()["desired_state"] == "RUNNING"
    assert json.loads(auth.read_text())["OPENAI_API_KEY"] == SENTINEL
    assert_no_persisted_secret(live)


async def test_actual_ssh_drops_banner_stderr_and_capability_failures_without_secret(codex_network):
    live, client, server, state, _, _, connections = codex_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    initial = await runtime(client, server)
    state.update(stdout="BANNER " + SENTINEL, stderr="ERROR auth.json " + SENTINEL, exit=0)
    malformed = await credential_check(client, server)
    assert malformed["credential_state"] == "CHECK_UNAVAILABLE" and malformed["reason_code"] == "INVALID_REMOTE_RESULT"
    assert malformed["key_readable"] is None and not malformed["check_completed"]
    state.update(exit=69)
    missing_tool = await credential_check(client, server)
    assert missing_tool["credential_state"] == "REMOTE_TOOL_UNAVAILABLE" and missing_tool["key_readable"] is None
    state.update(stdout=SENTINEL * 2000, stderr=SENTINEL * 2000, exit=0)
    bounded = await credential_check(client, server)
    assert bounded["credential_state"] == "CHECK_UNAVAILABLE" and bounded["reason_code"] == "CHECK_TIMEOUT"
    activity = (await client.get("/api/v1/activity")).json()
    logs = (await client.get(f"/api/v1/servers/{server['id']}/logs")).json()
    assert SENTINEL not in json.dumps([activity, logs])
    for endpoint in ("/configuration/export", "/diagnostics/exports"):
        exported = await client.post("/api/v1" + endpoint, json={} if endpoint == "/configuration/export" else None)
        assert exported.status_code == 200
        artifact = await client.get(exported.json()["download_url"])
        assert artifact.status_code == 200 and SENTINEL not in artifact.text
    assert (await runtime(client, server))["pid"] == initial["pid"] and len(connections) == 1
    assert_no_persisted_secret(live)


async def test_actual_remote_helper_preserves_all_file_failure_states(codex_network):
    live, client, server, state, _, codex_home, connections = codex_network
    state["use_codex_home"] = True
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    initial = await runtime(client, server)
    cases = [({}, "MISSING_KEY", False), ({"OPENAI_API_KEY": {"secret": SENTINEL}}, "INVALID_KEY", False)]
    for document, expected, readable in cases:
        write_auth(codex_home, document)
        result = await credential_check(client, server)
        assert result["credential_state"] == expected and result["key_readable"] is readable
        assert result["check_completed"]
    auth = write_auth(codex_home, {})
    auth.write_bytes(b"{invalid " + SENTINEL.encode())
    malformed = await credential_check(client, server)
    assert malformed["credential_state"] == "INVALID_JSON" and malformed["key_readable"] is None
    auth.write_bytes(b"x" * 65537)
    oversized = await credential_check(client, server)
    assert oversized["credential_state"] == "TOO_LARGE" and oversized["key_readable"] is None
    auth = write_auth(codex_home, {"OPENAI_API_KEY": SENTINEL})
    auth.chmod(0o000)
    try:
        unreadable = await credential_check(client, server)
        assert unreadable["credential_state"] == "UNREADABLE" and unreadable["key_readable"] is None
    finally:
        auth.chmod(0o600)
    assert len(connections) == 1 and (await runtime(client, server))["pid"] == initial["pid"]
    assert_no_persisted_secret(live)


async def test_missing_owned_mux_socket_never_falls_back_to_fresh_ssh(codex_network):
    _, client, server, state, home, _, connections = codex_network
    write_auth(home / ".codex", {"OPENAI_API_KEY": SENTINEL})
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    initial = await runtime(client, server)
    assert len(connections) == 1 and state["reads"] == 0
    # Delete only this fixture's recorded owned ControlMaster socket; preserve
    # the master itself, proxy listener and SSH server for the refusal check.
    socket = ROOT / ".run" / "s" / initial["run_id"][:10]
    assert socket.is_socket() and socket.is_relative_to(ROOT)
    socket.unlink()
    result = await credential_check(client, server)
    assert result["credential_state"] == "CHECK_UNAVAILABLE" and result["key_readable"] is None
    assert not result["ssh_connected"] and not result["check_completed"]
    assert len(connections) == 1 and state["reads"] == 0


async def test_modified_owned_config_refuses_check_before_remote_read(codex_network):
    _, client, server, state, home, _, connections = codex_network
    write_auth(home / ".codex", {"OPENAI_API_KEY": SENTINEL})
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    initial = await runtime(client, server)
    live = codex_network[0]
    config = live.data_dir / "tunnels" / (initial["run_id"] + ".conf")
    content = config.read_bytes()
    config.write_bytes(content + b"\n# isolated fixture tampering\n")
    try:
        response = await client.post(f"/api/v1/servers/{server['id']}/credentials/codex/check", json=CHECK_BODY)
        assert response.status_code == 409
        assert response.json()["code"] == "OWNERSHIP_MISMATCH"
        assert SENTINEL not in response.text and len(connections) == 1 and state["reads"] == 0
    finally:
        config.write_bytes(content)
