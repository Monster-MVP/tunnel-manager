"""Independent final frozen-app recovery gate; loopback resources only."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
from pathlib import Path
from uuid import uuid4

import asyncssh
import httpx
import pytest

from tests.app_paths import app_bundle_path

ROOT = Path(__file__).resolve().parents[2]
APP = app_bundle_path()
EXECUTABLE = APP / "Contents/MacOS/TunnelManager"


def free_port() -> int:
    with socket.socket() as channel:
        channel.bind(("127.0.0.1", 0))
        return channel.getsockname()[1]


def rpc(runtime: Path, command: str) -> dict:
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(2)
        channel.connect(str(runtime / "host.sock"))
        channel.sendall(json.dumps({"command": command}).encode() + b"\n")
        return json.loads(channel.recv(4096))


async def await_endpoint(runtime: Path, host: subprocess.Popen, previous_pid: int | None = None) -> dict:
    deadline = asyncio.get_running_loop().time() + 25
    while asyncio.get_running_loop().time() < deadline:
        assert host.poll() is None, "The test-owned native host exited unexpectedly"
        try:
            endpoint = json.loads((runtime / "endpoint.json").read_text())
            if endpoint["pid"] != previous_pid:
                async with httpx.AsyncClient(trust_env=False, timeout=.5) as client:
                    response = await client.get(endpoint["origin"] + "/healthz")
                    if response.status_code == 200 and response.json()["alive"]:
                        return endpoint
        except (OSError, ValueError, httpx.HTTPError):
            pass
        await asyncio.sleep(.1)
    pytest.fail("Frozen backend did not become available within 25 seconds")


async def authorized_client(runtime: Path, endpoint: dict) -> httpx.AsyncClient:
    value = rpc(runtime, "ticket")
    assert value["port"] == endpoint["port"]
    client = httpx.AsyncClient(base_url=endpoint["origin"], trust_env=False, timeout=15,
                              headers={"Origin": endpoint["origin"]})
    reply = await client.post("/api/v1/sessions/exchange", json={"ticket": value["ticket"]})
    assert reply.status_code == 200
    client.headers["X-CSRF-Token"] = reply.json()["csrf"]
    return client


async def wait_operation(client: httpx.AsyncClient, accepted: httpx.Response) -> dict:
    assert accepted.status_code == 202, accepted.text
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        operation = (await client.get(f"/api/v1/operations/{accepted.json()['operation_id']}")).json()
        if operation["status"] in {"FAILED", "SUCCEEDED"}:
            return operation
        await asyncio.sleep(.05)
    pytest.fail(f"Frozen operation did not finish: {operation}")


@pytest.mark.asyncio
async def test_frozen_native_watchdog_restores_owned_ssh_without_login_restore_flag():
    if not EXECUTABLE.is_file():
        pytest.skip("Final native bundle has not been built")
    tag = uuid4().hex[:6]
    data = ROOT / "var/tmp/native-reliability" / tag / "data"
    runtime = ROOT / ".run" / ("qn-" + tag)
    data.mkdir(parents=True, mode=0o700)
    connections = []
    requests = {"count": 0}

    class Peer(asyncssh.SSHServer):
        def connection_made(self, connection):
            self.connection = connection
            connections.append(connection)

        def connection_lost(self, exc):
            print("QA_NATIVE: fixture SSH connection closed", flush=True)

        def begin_auth(self, username):
            return False

        def server_requested(self, host, port):
            return host == "127.0.0.1" and port >= 1024

    async def command(process):
        if process.command.startswith("if command -v ss"):
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
            out, err = await child.communicate()
            process.stdout.write(out.decode())
            process.stderr.write(err.decode())
            process.exit(child.returncode)
        else:
            process.exit(69)

    async def proxy_request(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            requests["count"] += 1
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    key = asyncssh.generate_private_key("ssh-ed25519")
    ssh = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[key], server_factory=Peer,
                                process_factory=command, encoding="utf-8")
    known_hosts = data / "known_hosts"
    known_hosts.write_bytes(f"[127.0.0.1]:{ssh.get_port()} ".encode() + key.export_public_key())
    known_hosts.chmod(0o600)
    proxy = await asyncio.start_server(proxy_request, "127.0.0.1", 0)
    environment = os.environ.copy()
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX"):
        environment.pop(name, None)
    environment.update(PATH="/usr/bin:/bin:/usr/sbin:/sbin", TMPDIR=str(ROOT / "var/tmp"))
    log = (data.parent / "native.log").open("ab")
    host = await asyncio.to_thread(subprocess.Popen,
        [str(EXECUTABLE), "--service-host", "--runtime-dir", str(runtime), "--data-dir", str(data)],
        cwd=ROOT, env=environment, stdout=log, stderr=log, start_new_session=True)
    client = None
    evidence = []
    try:
        print("QA_NATIVE: boot", flush=True)
        endpoint = await await_endpoint(runtime, host)
        client = await authorized_client(runtime, endpoint)
        web = await client.get("/")
        assert web.status_code == 200
        assert web.content == (APP / "Contents/Resources/web/index.html").read_bytes()
        assert web.content == (ROOT / "var/build/web/index.html").read_bytes(), "Frozen bundle contains an outdated UI"
        evidence.append("frozen_backend_and_current_ui_with_no_development_PATH")
        print("QA_NATIVE: packaged UI ready", flush=True)
        assert (await client.patch("/api/v1/settings", json={"health_interval_s": 2, "connect_timeout_s": 3,
                  "probe_timeout_s": 2, "retry_base_s": 1, "retry_max_s": 5})).status_code == 200
        created = await client.post("/api/v1/servers", json={"name": "QA native owned recovery", "host": "127.0.0.1",
            "ssh_port": ssh.get_port(), "user": "qa", "mode": "CLASH_HTTP", "auto_reconnect": True,
            "restore_on_login": False, "proxy_port": proxy.sockets[0].getsockname()[1],
            "remote_proxy_port": free_port(), "health_url": "http://fixture.invalid/health", "expected_status": [200]})
        assert created.status_code == 201
        server = created.json()
        path = f"/api/v1/servers/{server['id']}"
        operation = await wait_operation(client, await client.post(path + "/actions/start"))
        assert operation["status"] == "SUCCEEDED", operation
        before = (await client.get(path + "/runtime")).json()
        assert before["state"] == "HEALTHY" and before["process_alive"] and before["http_status"] == 200
        evidence.append("frozen_backend_real_openssh_reverse_proxy_http_health")
        print("QA_NATIVE: real SSH healthy", flush=True)

        # Exact test-owned native child, direct parent and private process group
        # are verified before fault injection. No external PID is targeted.
        backend_pid = endpoint["pid"]
        parent = await asyncio.to_thread(subprocess.check_output,
            ["/bin/ps", "-o", "ppid=", "-p", str(backend_pid)], text=True)
        assert parent.strip() == str(host.pid)
        assert os.getpgid(backend_pid) == backend_pid
        assert os.getpgid(before["pid"]) == backend_pid
        os.kill(backend_pid, signal.SIGKILL)
        print("QA_NATIVE: backend fault injected", flush=True)
        await client.aclose()
        client = None
        recovered_endpoint = await await_endpoint(runtime, host, previous_pid=backend_pid)
        print("QA_NATIVE: new backend ready", flush=True)
        old_process = await asyncio.to_thread(subprocess.run,
            ["/bin/ps", "-o", "pid=,ppid=,pgid=,stat=", "-p", str(before["pid"])],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("QA_NATIVE: old owned SSH process snapshot " + old_process.stdout.strip(), flush=True)
        print("QA_NATIVE: fixture closed connections " + str([connection.is_closed() for connection in connections]), flush=True)
        assert old_process.returncode != 0, "Native cleanup stranded its old SSH child after backend crash"
        assert connections[0].is_closed(), "Old fixture connection still owns the reverse listener after crash"
        client = await authorized_client(runtime, recovered_endpoint)
        deadline = asyncio.get_running_loop().time() + 12
        while asyncio.get_running_loop().time() < deadline:
            after = (await client.get(path + "/runtime")).json()
            if after["state"] == "HEALTHY" and after["process_alive"] and after["pid"] != before["pid"]:
                break
            await asyncio.sleep(.1)
        else:
            pytest.fail(f"Watchdog failed to recover true SSH health without login restore: {after}")
        assert after["ssh_connected"] and after["remote_listener"] == "LISTENING" and after["http_status"] == 200
        persisted = (await client.get(path)).json()
        assert persisted["restore_on_login"] is False and persisted["desired_state"] == "RUNNING"
        assert requests["count"] >= 2
        evidence.append("watchdog_crash_recovers_enabled_auto_reconnect_profile_without_login_restore")
        print("QA_NATIVE: owned SSH recovered", flush=True)
        node = shutil.which("node")
        assert node, "Node is required by the browser acceptance harness, not by the packaged app"
        browser_child = await asyncio.create_subprocess_exec(node, str(ROOT / "tests/e2e/native-history.mjs"),
            cwd=ROOT, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        browser_input = {"origin": recovered_endpoint["origin"], "ticket": rpc(runtime, "ticket")["ticket"],
                         "name": server["name"], "server_id": server["id"]}
        try:
            out, err = await asyncio.wait_for(browser_child.communicate(json.dumps(browser_input).encode()), 35)
        except TimeoutError:
            browser_child.kill()
            await browser_child.wait()
            raise
        assert browser_child.returncode == 0, (out + err).decode()
        print(out.decode().strip(), flush=True)
        assert (await client.get(path + "/runtime")).json()["state"] == "HEALTHY"
        evidence.append("real_metrics_state_history_ui_websocket_staleness_and_browser_close_keeps_ssh_alive")
        stopped = await wait_operation(client, await client.post(path + "/actions/stop"))
        assert stopped["status"] == "SUCCEEDED"
        assert (await client.get(path + "/runtime")).json()["state"] == "STOPPED"
        assert proxy.is_serving()
        evidence.append("manual_stop_preserves_external_fixture_proxy")
        # Verify the bundled tinyproxy, not the Homebrew executable used by
        # source-only tests. This fixture also serves as a true local origin.
        current = (await client.get(path)).json()
        updated = await client.patch(path, headers={"If-Match": str(current["revision"])},
            json={"health_url": f"http://127.0.0.1:{proxy.sockets[0].getsockname()[1]}/health"})
        assert updated.status_code == 200
        managed_port = free_port()
        changed = await wait_operation(client, await client.put(path + "/mode",
            headers={"If-Match": str(updated.json()["revision"])},
            json={"mode": "MAC_DIRECT", "proxy_port": managed_port}))
        assert changed["status"] == "SUCCEEDED"
        direct = await wait_operation(client, await client.post(path + "/actions/start"))
        assert direct["status"] == "SUCCEEDED", direct
        direct_runtime = (await client.get(path + "/runtime")).json()
        assert direct_runtime["state"] == "HEALTHY" and direct_runtime["http_status"] == 200
        assert direct_runtime["direct_path_verification"] == "UNVERIFIED"
        _, writer = await asyncio.open_connection("127.0.0.1", managed_port)
        writer.close()
        await writer.wait_closed()
        evidence.append("bundled_tinyproxy_mac_direct_true_origin_health_with_restricted_PATH")
        stopped = await wait_operation(client, await client.post(path + "/actions/stop"))
        assert stopped["status"] == "SUCCEEDED"
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", managed_port)
        assert proxy.is_serving()
        evidence.append("managed_tinyproxy_listener_released_external_origin_preserved")
        print("QA_NATIVE: bundled proxy passed", flush=True)
    finally:
        if client:
            await client.aclose()
        if host.poll() is None:
            with contextlib.suppress(OSError, ValueError):
                rpc(runtime, "shutdown")
            deadline = asyncio.get_running_loop().time() + 10
            while host.poll() is None and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(.1)
            if host.poll() is None:
                # This Popen handle created only the isolated native host.
                host.terminate()
                await asyncio.to_thread(host.wait, timeout=5)
        log.close()
        ssh.close()
        for connection in connections:
            connection.abort()
            with contextlib.suppress(TimeoutError, OSError):
                await asyncio.wait_for(connection.wait_closed(), 2)
        await asyncio.wait_for(ssh.wait_closed(), 5)
        proxy.close()
        await asyncio.wait_for(proxy.wait_closed(), 5)
    assert host.returncode == 0
    assert not (runtime / "control.sock").exists() and not (runtime / "host.sock").exists()
    (ROOT / "var/reports/qa-native-recovery-evidence.json").write_text(
        json.dumps({"passed": evidence, "development_PATH": False, "runtime": str(runtime.relative_to(ROOT))}, indent=2) + "\n")
