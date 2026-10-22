"""Independent final frozen native host / bundled proxy / verified TLS proof."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import shlex
import ssl
import subprocess
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import asyncssh
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tests.integration.test_native_recovery import (
    APP,
    EXECUTABLE,
    ROOT,
    authorized_client,
    await_endpoint,
    free_port,
    rpc,
    wait_operation,
)


@pytest.mark.asyncio
async def test_frozen_native_bundled_proxy_real_verified_tls_and_latest_assets():
    assert EXECUTABLE.is_file(), "Final frozen bundle is required for this release gate"
    tag = uuid4().hex[:6]
    data = ROOT / "var/tmp/v2-frozen-tls" / tag / "data"
    runtime = ROOT / ".run" / ("qt-" + tag)
    data.mkdir(parents=True, mode=0o700)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    private_key = data / "generated-fixture.key"
    certificate_file = data / "generated-fixture.crt"
    private_key.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    private_key.chmod(0o600)
    certificate_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate_file, private_key)
    observed = {"requests": 0, "http_code": 200, "curl_commands": 0}
    connections = []

    async def origin_request(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            observed["requests"] += 1
            code = observed["http_code"]
            writer.write(f"HTTP/1.1 {code} TLSFixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    origin = await asyncio.start_server(origin_request, "127.0.0.1", 0, ssl=tls)
    origin_port = origin.sockets[0].getsockname()[1]

    class Peer(asyncssh.SSHServer):
        def connection_made(self, connection):
            connections.append(connection)

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
            assert "-k" not in arguments and "--insecure" not in arguments
            observed["curl_commands"] += 1
            child = await asyncio.create_subprocess_exec("/usr/bin/curl", *arguments[1:],
                env={"PATH": "/usr/bin:/bin", "CURL_CA_BUNDLE": str(certificate_file)},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            output, error = await child.communicate()
            process.stdout.write(output.decode())
            process.stderr.write(error.decode())
            process.exit(child.returncode)
        else:
            process.exit(69)

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    ssh = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[host_key], server_factory=Peer,
                                process_factory=command, encoding="utf-8")
    known = data / "known_hosts"
    known.write_bytes(f"[127.0.0.1]:{ssh.get_port()} ".encode() + host_key.export_public_key())
    known.chmod(0o600)
    environment = os.environ.copy()
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX"):
        environment.pop(name, None)
    environment.update(PATH="/usr/bin:/bin:/usr/sbin:/sbin", TMPDIR=str(ROOT / "var/tmp"))
    log = (data.parent / "native.log").open("ab")
    host = await asyncio.to_thread(subprocess.Popen,
        [str(EXECUTABLE), "--service-host", "--runtime-dir", str(runtime), "--data-dir", str(data)],
        cwd=ROOT, env=environment, stdout=log, stderr=log, start_new_session=True)
    client = None
    evidence = {"verified_tls": False, "development_PATH": False, "gui_double_click": "UNVERIFIED",
                "signature": "ad-hoc", "production_resources_used": False}
    managed_port = free_port()
    try:
        endpoint = await await_endpoint(runtime, host)
        client = await authorized_client(runtime, endpoint)
        build = ROOT / "var/build/web"
        frozen = APP / "Contents/Resources/web"
        source_files = {str(path.relative_to(build)) for path in build.rglob("*") if path.is_file()}
        frozen_files = {str(path.relative_to(frozen)) for path in frozen.rglob("*") if path.is_file()}
        assert source_files == frozen_files, "Frozen UI assets differ from the audited web build"
        for relative in source_files:
            assert (build / relative).read_bytes() == (frozen / relative).read_bytes(), relative
        homepage = await client.get("/")
        assert homepage.status_code == 200 and homepage.content == (build / "index.html").read_bytes()
        for asset in re.findall(r'(?:src|href)="(/assets/[^\"]+)"', homepage.text):
            response = await client.get(asset)
            assert response.status_code == 200 and response.content == (build / asset.lstrip("/")).read_bytes()
        evidence["source_frozen_assets_exact_match"] = True
        evidence["index_sha256"] = hashlib.sha256(homepage.content).hexdigest()
        assert (await client.patch("/api/v1/settings", json={"health_interval_s": 3600,
                   "connect_timeout_s": 3, "probe_timeout_s": 3})).status_code == 200
        response = await client.post("/api/v1/servers", json={"name": "冻结应用 · 真实 TLS 验收",
            "host": "127.0.0.1", "ssh_port": ssh.get_port(), "user": "fixture", "mode": "MAC_DIRECT",
            "proxy_port": managed_port, "remote_proxy_port": free_port(), "auto_reconnect": False,
            "health_url": f"https://localhost:{origin_port}/frozen", "expected_status": [200]})
        assert response.status_code == 201
        server = response.json()
        path = f"/api/v1/servers/{server['id']}"
        operation = await wait_operation(client, await client.post(path + "/actions/start"))
        assert operation["status"] == "SUCCEEDED", operation
        fresh = (await client.get(path + "/runtime")).json()
        assert fresh["state"] == "HEALTHY" and fresh["proxy_health"] == "HEALTHY"
        assert fresh["ssh_connected"] and fresh["remote_listener"] == "LISTENING"
        assert fresh["http_status"] == 200 and fresh["http_connect_status"] == 200
        assert fresh["tls_completed_ms"] > 0 and fresh["tls_handshake_ms"] >= 0
        assert fresh["ssh_latency_ms"] > 0 and fresh["total_ms"] > 0
        assert observed["requests"] > 0 and observed["curl_commands"] > 0
        parent = await asyncio.to_thread(subprocess.check_output,
            ["/bin/ps", "-o", "ppid=", "-p", str(endpoint["pid"])], text=True)
        assert parent.strip() == str(host.pid)
        evidence.update(verified_tls=True, bundled_tinyproxy=True, actual_system_openssh=True,
            measurements={key: fresh[key] for key in ("http_status", "http_connect_status", "tls_completed_ms",
                                                     "tls_handshake_ms", "ssh_latency_ms", "total_ms")})
        observed["http_code"] = 503
        probe = await wait_operation(client, await client.post(path + "/probes"))
        assert probe["status"] == "SUCCEEDED"
        degraded = (await client.get(path + "/runtime")).json()
        assert degraded["state"] == "DEGRADED" and degraded["proxy_health"] == "UNHEALTHY"
        assert degraded["http_status"] == 503 and degraded["http_connect_status"] == 200
        assert degraded["pid"] == fresh["pid"] and degraded["ssh_connected"]
        assert (await client.get(path)).json()["desired_state"] == "RUNNING"
        evidence["tls_http503_degrades_without_restarting_ssh_or_changing_intent"] = True
        stopped = await wait_operation(client, await client.post(path + "/actions/stop"))
        assert stopped["status"] == "SUCCEEDED"
        final = (await client.get(path + "/runtime")).json()
        assert final["state"] == "STOPPED" and not final["process_alive"]
        assert final["proxy_health"] == "UNKNOWN" and final["http_connect_status"] is None
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", managed_port)
        assert origin.is_serving()
        evidence["stop_releases_only_owned_proxy_and_clears_current_health"] = True
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
                host.terminate()  # Exact Popen handle created by this isolated test only.
                await asyncio.to_thread(host.wait, timeout=5)
        log.close()
        ssh.close()
        for connection in connections:
            connection.abort()
            with contextlib.suppress(TimeoutError, OSError):
                await asyncio.wait_for(connection.wait_closed(), 2)
        await asyncio.wait_for(ssh.wait_closed(), 5)
        origin.close()
        await origin.wait_closed()
    assert host.returncode == 0
    assert not (runtime / "host.sock").exists() and not (runtime / "control.sock").exists()
    evidence["fixture_cleanup"] = True
    (ROOT / "var/reports/v2-frozen-tls-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
