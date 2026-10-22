"""Independent API/real OpenSSH fault injection against loopback fixtures only."""
from __future__ import annotations

import asyncio
import contextlib
import re
import shlex
import socket

import asyncssh
import httpx
import pytest


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


@pytest.fixture
async def live_network(live):
    connections = []

    class Server(asyncssh.SSHServer):
        def connection_made(self, connection):
            connections.append(connection)

        def begin_auth(self, username):
            return False

        def server_requested(self, host, port):
            return host == "127.0.0.1" and port >= 1024

    async def command(process):
        if process.command.startswith("if command -v ss"):
            if not status["listener_capable"]:
                process.exit(69)
                return
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
            assert arguments[0:2] == ["curl", "-q"]
            child = await asyncio.create_subprocess_exec("/usr/bin/curl", *arguments[1:],
                env={"PATH": "/usr/bin:/bin"}, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await child.communicate()
            process.stdout.write(out.decode())
            process.stderr.write(err.decode())
            process.exit(child.returncode)
        else:
            process.exit(69)

    # A fixture key is generated in memory. User private keys are never opened.
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    ssh = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[host_key], server_factory=Server,
                                process_factory=command, encoding="utf-8")
    known = live.data_dir / "known_hosts"
    known.write_bytes(f"[127.0.0.1]:{ssh.get_port()} ".encode() + host_key.export_public_key())
    known.chmod(0o600)
    status = {"code": 200, "requests": 0, "delay_s": 0, "listener_capable": True}

    async def proxy_request(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            status["requests"] += 1
            await asyncio.sleep(status["delay_s"])
            writer.write(f"HTTP/1.1 {status['code']} Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
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
        settings = await client.patch("/api/v1/settings", json={"health_interval_s": 2, "connect_timeout_s": 3,
                      "probe_timeout_s": 2, "retry_base_s": 1, "retry_max_s": 5, "failure_threshold": 2})
        assert settings.status_code == 200
        created = await client.post("/api/v1/servers", json={"name": "QA actual loopback", "host": "127.0.0.1",
            "ssh_port": ssh.get_port(), "user": "qa", "mode": "CLASH_HTTP", "auto_reconnect": True,
            "proxy_port": proxy.sockets[0].getsockname()[1], "remote_proxy_port": free_port(),
            "health_url": "http://fixture.invalid/health", "expected_status": [200]})
        assert created.status_code == 201
        try:
            yield live, client, created.json(), status, proxy, ssh, connections
        finally:
            await client.post(f"/api/v1/servers/{created.json()['id']}/actions/stop")
            await asyncio.sleep(.1)
            ssh.close()
            await ssh.wait_closed()
            for connection in connections:
                connection.close()
                await connection.wait_closed()
            proxy.close()
            await proxy.wait_closed()


async def action(client, server, name, **options):
    path = f"/api/v1/servers/{server['id']}/probes" if name == "probe" else f"/api/v1/servers/{server['id']}/actions/{name}"
    accepted = await client.post(path, **options)
    assert accepted.status_code == 202, accepted.text
    deadline = asyncio.get_running_loop().time() + 7
    while asyncio.get_running_loop().time() < deadline:
        operation = (await client.get(f"/api/v1/operations/{accepted.json()['operation_id']}")).json()
        if operation["status"] in {"SUCCEEDED", "FAILED"}:
            return operation
        await asyncio.sleep(.05)
    pytest.fail(f"{name} operation unfinished: {operation}")


async def runtime(client, server):
    return (await client.get(f"/api/v1/servers/{server['id']}/runtime")).json()


@pytest.mark.asyncio
async def test_http_failure_listener_alive_has_degraded_evidence_and_recovers(live_network):
    _, client, server, status, proxy, _, _ = live_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    first = await runtime(client, server)
    assert first["state"] == "HEALTHY" and first["http_status"] == 200
    status["code"] = 503
    for _ in range(2):
        response = await client.post(f"/api/v1/servers/{server['id']}/probes")
        assert response.status_code == 202
        await asyncio.sleep(.2)
    degraded = await runtime(client, server)
    assert degraded["state"] == "DEGRADED"
    assert degraded["process_alive"] and degraded["ssh_connected"] and degraded["remote_listener"] == "LISTENING"
    assert degraded["http_status"] == 503 and degraded["consecutive_failures"] >= 2
    assert degraded["pid"] == first["pid"] and degraded["reconnect_count"] == 0
    status["code"] = 200
    await client.post(f"/api/v1/servers/{server['id']}/probes")
    await asyncio.sleep(.2)
    recovered = await runtime(client, server)
    assert recovered["state"] == "HEALTHY" and recovered["pid"] == first["pid"]
    assert recovered["consecutive_failures"] == 0 and recovered["last_recovered_at"]
    metrics = (await client.get(f"/api/v1/servers/{server['id']}/metrics")).json()
    assert {row["http_status"] for row in metrics} == {200, 503}
    assert all(row["total_ms"] is not None for row in metrics)
    assert proxy.is_serving() and status["requests"] >= 4


@pytest.mark.asyncio
async def test_real_disconnect_reconnect_and_manual_stop_cancel_retry(live_network):
    _, client, server, _, proxy, _, connections = live_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    first = await runtime(client, server)
    for connection in list(connections):
        connection.close()
        await connection.wait_closed()
    deadline = asyncio.get_running_loop().time() + 12
    while asyncio.get_running_loop().time() < deadline:
        latest = await runtime(client, server)
        if latest["state"] == "HEALTHY" and latest["process_alive"] and latest["pid"] and latest["pid"] != first["pid"]:
            break
        await asyncio.sleep(.1)
    else:
        pytest.fail(f"No healthy reconnection: {latest}")
    assert latest["reconnect_count"] >= 1
    assert (await action(client, server, "stop"))["status"] == "SUCCEEDED"
    await asyncio.sleep(1.5)
    assert (await runtime(client, server))["state"] == "STOPPED"
    assert (await client.get(f"/api/v1/servers/{server['id']}")).json()["desired_state"] == "STOPPED"
    assert proxy.is_serving()


@pytest.mark.asyncio
async def test_concurrent_idempotent_api_starts_and_stops_one_master(live_network):
    _, client, server, _, proxy, _, _ = live_network
    path = f"/api/v1/servers/{server['id']}/actions/"
    replies = await asyncio.gather(*(client.post(path + "start", headers={"Idempotency-Key": "parallel-start"}) for _ in range(8)))
    assert all(reply.status_code == 202 for reply in replies)
    assert len({reply.json()["operation_id"] for reply in replies}) == 1
    deadline = asyncio.get_running_loop().time() + 7
    while asyncio.get_running_loop().time() < deadline:
        current = await runtime(client, server)
        if current["state"] == "HEALTHY":
            break
        await asyncio.sleep(.05)
    assert current["state"] == "HEALTHY", current
    edited = await client.patch(f"/api/v1/servers/{server['id']}", json={"ssh_port": 12345},
                               headers={"If-Match": str((await client.get(f"/api/v1/servers/{server['id']}")).json()["revision"])})
    assert edited.status_code == 409 and edited.json()["code"] == "ACTIVE_RESOURCE"
    replies = await asyncio.gather(*(client.post(path + "stop", headers={"Idempotency-Key": "parallel-stop"}) for _ in range(8)))
    assert len({reply.json()["operation_id"] for reply in replies}) == 1
    await asyncio.sleep(.3)
    stopped = await runtime(client, server)
    assert stopped["state"] == "STOPPED" and not stopped["process_alive"]
    assert proxy.is_serving()


@pytest.mark.asyncio
async def test_remote_port_conflict_reports_failed_operation_preserving_owner(live_network):
    _, client, server, _, proxy, _, _ = live_network
    owner = await asyncio.start_server(lambda reader, writer: writer.close(), "127.0.0.1", server["remote_proxy_port"])
    try:
        operation = await action(client, server, "start")
        assert operation["status"] == "FAILED", operation
        assert (await runtime(client, server))["state"] == "PORT_CONFLICT"
        assert owner.is_serving() and proxy.is_serving()
    finally:
        owner.close()
        await owner.wait_closed()


@pytest.mark.asyncio
async def test_unknown_host_requires_auth_without_blind_accept(live_network):
    live, client, server, _, proxy, _, _ = live_network
    (live.data_dir / "known_hosts").unlink()
    operation = await action(client, server, "start")
    assert operation["status"] == "FAILED"
    latest = await runtime(client, server)
    assert latest["state"] == "AUTH_REQUIRED" and not latest["process_alive"]
    assert not (live.data_dir / "known_hosts").exists()
    assert proxy.is_serving()


@pytest.mark.asyncio
async def test_overview_and_runtime_never_claim_healthy_after_observed_child_exit(live_network):
    _, client, server, _, _, _, connections = live_network
    # A long interval exposes the period between direct process evidence and
    # the next scheduled end-to-end probe without injecting production faults.
    changed = await client.patch("/api/v1/settings", json={"health_interval_s": 3600})
    assert changed.status_code == 200
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    await asyncio.sleep(.4)
    for connection in list(connections):
        connection.close()
        await connection.wait_closed()
    deadline = asyncio.get_running_loop().time() + 5
    while asyncio.get_running_loop().time() < deadline:
        latest = await runtime(client, server)
        if not latest["process_alive"]:
            break
        await asyncio.sleep(.05)
    assert not latest["process_alive"], latest
    assert latest["state"] != "HEALTHY", latest
    overview = (await client.get("/api/v1/overview")).json()["runtimes"][server["id"]]
    assert not overview["process_alive"] and overview["state"] != "HEALTHY", overview


@pytest.mark.asyncio
async def test_probe_timeout_is_bounded_with_alive_ssh_and_listener(live_network):
    _, client, server, status, proxy, _, _ = live_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    initial = await runtime(client, server)
    assert (await client.patch("/api/v1/settings", json={"probe_timeout_s": 1})).status_code == 200
    status["delay_s"] = 2.5
    started = asyncio.get_running_loop().time()
    operation = await action(client, server, "probe")
    assert operation["status"] == "SUCCEEDED"
    assert asyncio.get_running_loop().time() - started < 4
    timed_out = await runtime(client, server)
    assert timed_out["state"] == "DEGRADED" and timed_out["http_status"] is None
    assert timed_out["process_alive"] and timed_out["ssh_connected"]
    assert timed_out["remote_listener"] == "LISTENING"
    assert timed_out["pid"] == initial["pid"] and timed_out["reconnect_count"] == 0
    assert proxy.is_serving()
    status["delay_s"] = 0


@pytest.mark.asyncio
async def test_missing_remote_listener_tool_remains_unavailable_without_fake_health(live_network):
    _, client, server, status, _, _, _ = live_network
    status["listener_capable"] = False
    await action(client, server, "start")
    value = await runtime(client, server)
    assert value["state"] == "DEGRADED" and value["monitoring_capability"] == "PARTIAL"
    assert value["process_alive"] and value["ssh_connected"]
    assert value["remote_listener"] == "UNAVAILABLE"
    assert value["http_status"] is None and value["proxy_health"] != "HEALTHY"
