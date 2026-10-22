"""Real system OpenSSH / real TCP / real curl loopback integration.

The AsyncSSH fixture is a controlled test SSH server.  Its Linux ``ss`` command
adapter inspects a real TCP listener because the fixture runs on macOS.  No
production SSH server or proxy is used, and no health response is fabricated.
"""

import asyncio
import contextlib
import re
import shlex
import socket
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import asyncssh
import pytest
from app.db.repository import Repository
from app.tunnels.manager import EngineError, TunnelManager
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LoopbackSSH(asyncssh.SSHServer):
    connections: ClassVar[list] = []
    test_ca: ClassVar[str | None] = None

    def connection_made(self, conn):
        self.connections.append(conn)

    def begin_auth(self, username):
        return False

    def server_requested(self, listen_host, listen_port):
        return listen_host == "127.0.0.1" and listen_port >= 1024


async def remote_command(process):
    command = process.command
    if command.startswith("if command -v ss"):
        port = int(re.search(r"sport = :(\d+)", command)[1])
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            process.exit(0)
        except OSError:
            process.exit(1)
    elif command.startswith("curl "):
        args = shlex.split(command)
        assert args[0:2] == ["curl", "-q"]
        environment = {"PATH": "/usr/bin:/bin"}
        if LoopbackSSH.test_ca:
            environment["CURL_CA_BUNDLE"] = LoopbackSSH.test_ca
        child = await asyncio.create_subprocess_exec("/usr/bin/curl", *args[1:], stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.PIPE, env=environment)
        out, err = await child.communicate()
        process.stdout.write(out.decode())
        process.stderr.write(err.decode())
        process.exit(child.returncode)
    else:
        process.exit(69)


@pytest.fixture
async def network(tmp_path):
    assert tmp_path.is_relative_to(Path(__file__).resolve().parents[2])
    repo = Repository(tmp_path / "data")
    hostkey = asyncssh.generate_private_key("ssh-ed25519")
    LoopbackSSH.connections = []
    LoopbackSSH.test_ca = None
    ssh = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[hostkey], server_factory=LoopbackSSH,
                                process_factory=remote_command, encoding="utf-8")
    ssh_port = ssh.get_port()
    known_hosts = repo.data_dir / "known_hosts"
    known_hosts.write_bytes(f"[127.0.0.1]:{ssh_port} ".encode() + hostkey.export_public_key())
    known_hosts.chmod(0o600)
    status = {"code": 200, "requests": 0}
    async def http(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            status["requests"] += 1
            code = status["code"]
            writer.write(f"HTTP/1.1 {code} Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".encode())
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()
    proxy = await asyncio.start_server(http, "127.0.0.1", 0)
    proxy_port = proxy.sockets[0].getsockname()[1]
    repo.update_settings({"health_interval_s": 2, "retry_base_s": 1, "retry_max_s": 5, "connect_timeout_s": 3})
    manager = TunnelManager(repo.data_dir, repo)
    profile = repo.create_server({"name": "loopback-actual", "host": "127.0.0.1", "ssh_port": ssh_port,
                                  "user": "testuser", "mode": "CLASH_HTTP", "proxy_port": proxy_port,
                                  "remote_proxy_port": unused_port(), "health_url": "http://example.invalid/health",
                                  "expected_status": [200], "auto_reconnect": True})
    yield manager, repo, profile, status, proxy, ssh
    await manager.close()
    ssh.close()
    await ssh.wait_closed()
    for connection in LoopbackSSH.connections:
        connection.close()
        await connection.wait_closed()
    proxy.close()
    await proxy.wait_closed()
    repo.close()


@pytest.mark.asyncio
async def test_wizard_real_tunnel_test_preserves_stopped_intent_and_cleans_child(network):
    manager, repo, server, status, _, _ = network
    result = await manager.test_connection(server["id"], "proxy")
    assert result["passed"] and result["proxy_ok"] and result["connection_ok"], result
    assert result["runtime"]["state"] == "HEALTHY" and status["requests"] > 0
    assert result["stopped_after_test"] and result["final_runtime"]["state"] == "STOPPED"
    assert repo.get_server(server["id"])["desired_state"] == "STOPPED"
    assert not manager._runs and server["id"] not in manager._monitors


@pytest.mark.asyncio
async def test_wizard_distinguishes_live_ssh_from_failed_proxy_request(network):
    manager, repo, server, status, _, _ = network
    status["code"] = 503
    connection = await manager.test_connection(server["id"], "connection")
    assert connection["passed"] and connection["connection_ok"] and not connection["proxy_ok"]
    proxy = await manager.test_connection(server["id"], "proxy")
    assert not proxy["passed"] and proxy["runtime"]["http_status"] == 503
    assert repo.get_server(server["id"])["desired_state"] == "STOPPED"
    assert not manager._runs


@pytest.mark.asyncio
async def test_real_tinyproxy_and_verified_https(network):
    manager, repo, server, _, _, _ = network
    binary = Path("/opt/homebrew/opt/tinyproxy/bin/tinyproxy")
    if not binary.exists():
        pytest.skip("isolated managed tinyproxy binary is unavailable")
    # Only a newly generated fixture key is written; no user key is inspected.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
                   .not_valid_after(datetime.now(UTC) + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .sign(key, hashes.SHA256()))
    key_path, cert_path = repo.data_dir / "fixture.key", repo.data_dir / "fixture.crt"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    async def https(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    origin = await asyncio.start_server(https, "127.0.0.1", 0, ssl=context)
    origin_port = origin.sockets[0].getsockname()[1]
    LoopbackSSH.test_ca = str(cert_path)
    manager.proxy.tinyproxy_executable = str(binary)
    repo.update_server(server["id"], {"mode": "MAC_DIRECT", "proxy_port": unused_port(),
                                     "health_url": f"https://localhost:{origin_port}/health"})
    try:
        runtime = await manager.start(server["id"])
        assert runtime["state"] == "HEALTHY", runtime
        assert runtime["tls_completed_ms"] > 0
        assert runtime["tls_handshake_ms"] >= 0
        assert runtime["http_connect_status"] == 200
        assert runtime["ssh_latency_ms"] >= 0 and runtime["last_success_at"]
        assert manager.proxy._managed
        await manager.stop(server["id"])
        assert not manager.proxy._managed
    finally:
        LoopbackSSH.test_ca = None
        origin.close()
        await origin.wait_closed()


@pytest.mark.asyncio
async def test_real_openssh_forward_curl_stop_and_status_failure(network):
    manager, repo, server, status, external_proxy, _ = network
    runtime = await manager.start(server["id"])
    assert runtime["state"] == "HEALTHY", runtime
    assert runtime["process_alive"] and runtime["ssh_connected"]
    assert runtime["remote_listener"] == "LISTENING"
    assert runtime["http_status"] == 200
    assert runtime["total_ms"] is not None
    assert runtime["tls_completed_ms"] is None
    pid = runtime["pid"]
    status["code"] = 503
    degraded = await manager.probe(server["id"])
    assert degraded["state"] == "DEGRADED"
    assert degraded["http_status"] == 503
    assert degraded["reason_code"] == "HTTP_STATUS_UNEXPECTED"
    assert degraded["pid"] == pid  # upstream failure must not restart SSH
    assert len(repo.samples(server["id"])) >= 2
    stopped = await manager.stop(server["id"])
    assert stopped["state"] == "STOPPED"
    assert not manager._runs
    assert external_proxy.is_serving()  # dependency is never stopped


@pytest.mark.asyncio
async def test_real_remote_port_conflict_does_not_kill_owner(network):
    manager, _, server, _, _, _ = network
    owner = await asyncio.start_server(lambda reader, writer: writer.close(), "127.0.0.1", server["remote_proxy_port"])
    try:
        runtime = await manager.start(server["id"])
        assert runtime["state"] == "PORT_CONFLICT", runtime
        assert owner.is_serving()
        assert not manager._runs
    finally:
        owner.close()
        await owner.wait_closed()


@pytest.mark.asyncio
async def test_real_unknown_host_key_requires_auth(network):
    manager, repo, server, _, _, _ = network
    (repo.data_dir / "known_hosts").unlink()
    runtime = await manager.start(server["id"])
    assert runtime["state"] == "AUTH_REQUIRED", runtime
    assert not manager._runs


@pytest.mark.asyncio
async def test_tampered_process_nonce_refuses_control(network):
    manager, _, server, _, _, _ = network
    assert (await manager.start(server["id"]))["state"] == "HEALTHY"
    handle = manager._runs[server["id"]]
    nonce = handle.nonce
    handle.nonce = "incorrect"
    try:
        with pytest.raises(EngineError) as raised:
            await manager.stop(server["id"])
        assert raised.value.code == "OWNERSHIP_MISMATCH"
        assert handle.process.returncode is None
    finally:
        handle.nonce = nonce
        await manager.stop(server["id"])


@pytest.mark.asyncio
async def test_real_disconnect_reconnects_and_manual_stop_stays_stopped(network):
    manager, repo, server, _, _, _ = network
    assert (await manager.start(server["id"]))["state"] == "HEALTHY"
    first = manager._runs[server["id"]]
    for connection in list(LoopbackSSH.connections):
        connection.close()
        await connection.wait_closed()
    deadline = asyncio.get_running_loop().time() + 12
    while asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.1)
        run = manager._runs.get(server["id"])
        if run and run is not first and manager.snapshot(server["id"])["state"] == "HEALTHY":
            break
    else:
        pytest.fail(f"No healthy reconnection: {manager.snapshot(server['id'])}")
    assert manager.snapshot(server["id"])["reconnect_count"] >= 1
    await manager.stop(server["id"])
    await asyncio.sleep(1.5)
    assert manager.snapshot(server["id"])["state"] == "STOPPED"
    assert repo.get_server(server["id"])["desired_state"] == "STOPPED"
    assert not manager._runs


@pytest.mark.asyncio
async def test_concurrent_starts_create_one_real_master(network):
    manager, _, server, _, _, _ = network
    results = await asyncio.gather(*(manager.start(server["id"]) for _ in range(6)))
    assert all(result["state"] == "HEALTHY" for result in results)
    assert len({result["pid"] for result in results}) == 1
    assert len(manager._runs) == 1
    await manager.stop(server["id"])


@pytest.mark.asyncio
async def test_stop_storage_failure_does_not_signal_running_child(network, monkeypatch):
    manager, repo, server, _, _, _ = network
    assert (await manager.start(server["id"]))["state"] == "HEALTHY"
    handle = manager._runs[server["id"]]
    original = repo.update_server
    def failed_write(*_args, **_kwargs):
        raise OSError("fixture storage unavailable")
    monkeypatch.setattr(repo, "update_server", failed_write)
    with pytest.raises(EngineError) as raised:
        await manager.stop(server["id"])
    assert raised.value.code == "STORAGE_UNAVAILABLE"
    assert handle.process.returncode is None
    monkeypatch.setattr(repo, "update_server", original)
    await manager.stop(server["id"])


@pytest.mark.asyncio
async def test_changed_generated_config_is_rejected_before_ssh_exec(network):
    manager, _, server, _, _, _ = network
    assert (await manager.start(server["id"]))["state"] == "HEALTHY"
    handle = manager._runs[server["id"]]
    original = handle.config_path.read_text()
    marker = handle.config_path.parent / "must-not-exist"
    handle.config_path.write_text(original + f"    LocalCommand touch {marker}\n")
    try:
        with pytest.raises(EngineError) as raised:
            await manager.probe(server["id"])
        assert raised.value.code == "OWNERSHIP_MISMATCH"
        assert not marker.exists()
        assert handle.process.returncode is None
    finally:
        handle.config_path.write_text(original)
        await manager.stop(server["id"])


@pytest.mark.asyncio
async def test_mode_unavailable_preflight_preserves_running_master(network):
    manager, repo, server, _, _, _ = network
    assert (await manager.start(server["id"]))["state"] == "HEALTHY"
    pid = manager.snapshot(server["id"])["pid"]
    with pytest.raises(EngineError) as raised:
        await manager.set_mode(server["id"], "CLASH_HTTP", unused_port())
    assert raised.value.code == "DEPENDENCY_UNAVAILABLE"
    assert manager.snapshot(server["id"])["pid"] == pid
    assert repo.get_server(server["id"])["proxy_port"] == server["proxy_port"]
