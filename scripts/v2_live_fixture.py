"""Project-local real SSH/tinyproxy/verified TLS evidence fixture for V2 UI audits."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import asyncssh
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]


def project_path(value: str) -> Path:
    path = Path(value).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("Fixture paths must stay inside the project")
    return path


def free_port() -> int:
    with socket.socket() as channel:
        channel.bind(("127.0.0.1", 0))
        return channel.getsockname()[1]


def private_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
    path.chmod(0o600)


def rpc(path: Path, command: str) -> dict:
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(3)
        channel.connect(str(path))
        channel.sendall(json.dumps({"command": command}).encode() + b"\n")
        return json.loads(channel.recv(8192))


async def wait_operation(client: httpx.AsyncClient, response: httpx.Response) -> dict:
    response.raise_for_status()
    deadline = asyncio.get_running_loop().time() + 20
    while asyncio.get_running_loop().time() < deadline:
        result = await client.get(f"/api/v1/operations/{response.json()['operation_id']}")
        result.raise_for_status()
        operation = result.json()
        if operation["status"] in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            return operation
        await asyncio.sleep(.05)
    raise TimeoutError("Actual fixture operation did not finish")


async def run(args) -> None:
    app_path = project_path(args.app_path)
    executable = app_path / "Contents/MacOS/TunnelManager"
    if args.packaged and not executable.is_file():
        raise FileNotFoundError("The final project-local app has not been built")
    tag = uuid4().hex[:6]
    data = ROOT / "var/tmp/v2-live" / tag / "data"
    runtime = ROOT / ".run" / ("vf-" + tag)
    data.mkdir(parents=True, mode=0o700)
    runtime.mkdir(parents=True, mode=0o700)
    credential_home = data / "synthetic-codex"
    credential_file = credential_home / "auth.json"
    if args.credential_fixture:
        credential_home.mkdir(mode=0o700)
        sys.path.insert(0, str(ROOT / "apps/backend"))
        from app.monitoring.codex_credentials import build_remote_codex_command
        credential_command = build_remote_codex_command()
    else:
        credential_command = None

    def credential_case(value: str) -> None:
        if not args.credential_fixture:
            raise ValueError("Credential fixture is not enabled")
        if credential_file.exists():
            credential_file.unlink()
        bodies = {
            "READABLE": json.dumps({"OPENAI_API_KEY": "SYNTHETIC-CREDENTIAL-CANARY-NOT-A-REAL-KEY"}),
            "MIXED": json.dumps({"auth_mode": "chatgpt", "OPENAI_API_KEY": "SYNTHETIC-CREDENTIAL-CANARY-NOT-A-REAL-KEY",
                                 "tokens": {"access_token": "SYNTHETIC-OAUTH-NOT-A-REAL-TOKEN"}}),
            "OAUTH_ONLY": json.dumps({"auth_mode": "chatgpt", "OPENAI_API_KEY": None,
                                      "tokens": {"access_token": "SYNTHETIC-OAUTH-NOT-A-REAL-TOKEN"}}),
            "MISSING_KEY": "{}", "INVALID_KEY": json.dumps({"OPENAI_API_KEY": 123}),
            "INVALID_JSON": "{", "TOO_LARGE": " " * 65537,
            "UNREADABLE": json.dumps({"OPENAI_API_KEY": "SYNTHETIC-CREDENTIAL-CANARY-NOT-A-REAL-KEY"}),
        }
        if value == "NOT_FOUND":
            return
        if value not in bodies:
            raise ValueError("Unknown synthetic credential case")
        credential_file.write_text(bodies[value])
        credential_file.chmod(0o644 if value == "UNREADABLE" else 0o600)

    if args.credential_fixture:
        credential_case("READABLE")
    certificate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(certificate_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(certificate_key, hashes.SHA256()))
    key_file, cert_file = data / "fixture.key", data / "fixture.crt"
    key_file.write_bytes(certificate_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_file.chmod(0o600)
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_file, key_file)
    status = {"healthy": 200, "degraded": 503, "requests": 0, "credential_checks": 0}
    connections: list[asyncssh.SSHServerConnection] = []

    async def http(reader, writer):
        try:
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
            target = header.split(b" ")[1].decode("ascii", "replace")
            code = status["degraded"] if target.startswith("/degraded") else status["healthy"]
            status["requests"] += 1
            body = f"actual fixture HTTP {code}".encode()
            writer.write(f"HTTP/1.1 {code} Fixture\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
            await writer.drain()
        except (OSError, TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    origin = await asyncio.start_server(http, "127.0.0.1", 0, ssl=tls)
    origin_port = origin.sockets[0].getsockname()[1]

    class Peer(asyncssh.SSHServer):
        def connection_made(self, connection):
            connections.append(connection)

        def begin_auth(self, username):
            return False

        def server_requested(self, host, port):
            return host == "127.0.0.1" and port >= 1024

    async def command(process):
        if credential_command is not None and process.command == credential_command:
            status["credential_checks"] += 1
            child = await asyncio.create_subprocess_exec(
                "/bin/sh", "-c", credential_command,
                env={"PATH": "/usr/bin:/bin", "HOME": str(data), "CODEX_HOME": str(credential_home),
                     "TMPDIR": str(ROOT / "var/tmp")},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            output, error = await child.communicate()
            process.stdout.write(output.decode())
            process.stderr.write(error.decode())
            process.exit(child.returncode)
        elif process.command.startswith("if command -v ss"):
            match = re.search(r"sport = :(\d+)", process.command)
            if not match:
                process.exit(69)
                return
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", int(match[1]))
                writer.close()
                await writer.wait_closed()
                process.exit(0)
            except OSError:
                process.exit(1)
        elif process.command.startswith("curl "):
            arguments = shlex.split(process.command)
            assert arguments[:2] == ["curl", "-q"]
            child = await asyncio.create_subprocess_exec("/usr/bin/curl", *arguments[1:],
                env={"PATH": "/usr/bin:/bin", "CURL_CA_BUNDLE": str(cert_file)},
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
    unknown = await asyncssh.listen("127.0.0.1", 0,
        server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")], server_factory=Peer,
        process_factory=command, encoding="utf-8")
    (data / "known_hosts").write_bytes(f"[127.0.0.1]:{ssh.get_port()} ".encode() + host_key.export_public_key())
    (data / "known_hosts").chmod(0o600)
    tinyproxy = app_path / "Contents/Resources/tinyproxy"
    if args.packaged and not tinyproxy.is_file():
        raise FileNotFoundError("The selected project-local app has no bundled tinyproxy")
    if not tinyproxy.is_file():
        tinyproxy = Path("/opt/homebrew/opt/tinyproxy/bin/tinyproxy")
    proxy_port = free_port()
    config = data / "external-fixture-tinyproxy.conf"
    config.write_text(f'Port {proxy_port}\nListen 127.0.0.1\nTimeout 10\nMaxClients 32\nAllow 127.0.0.1\nLogLevel Error\nLogFile "{data / "tinyproxy.log"}"\nPidFile "{data / "tinyproxy.pid"}"\n', encoding="utf-8")
    config.chmod(0o600)
    proxy_log = (data / "proxy-process.log").open("ab")
    proxy = await asyncio.to_thread(subprocess.Popen, [str(tinyproxy), "-d", "-c", str(config)], cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "TMPDIR": str(ROOT / "var/tmp")}, stdout=proxy_log, stderr=proxy_log)
    backend_log = (data / "backend.log").open("ab")
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(ROOT / "var/tmp")}
    ipc_socket = runtime / ("host.sock" if args.packaged else "control.sock")
    if args.packaged:
        for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "CONDA_PREFIX"):
            environment.pop(name, None)
        environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        command_args = [str(executable), "--service-host", "--data-dir", str(data), "--runtime-dir", str(runtime)]
    else:
        environment["PYTHONPATH"] = str(ROOT / "apps/backend")
        command_args = [str(ROOT / ".venv/bin/python"), "-m", "app.bootstrap", "--data-dir", str(data),
            "--runtime-dir", str(runtime), "--web-dir", str(project_path(args.web_dir)), "--port", "0",
            "--tinyproxy-executable", str(tinyproxy)]
    backend = await asyncio.to_thread(subprocess.Popen, command_args, cwd=ROOT, env=environment, stdout=backend_log,
        stderr=backend_log, start_new_session=True)
    client = None
    control = None
    finished = asyncio.Event()
    try:
        deadline = asyncio.get_running_loop().time() + 15
        while asyncio.get_running_loop().time() < deadline:
            if backend.poll() is not None or proxy.poll() is not None:
                raise RuntimeError("Fixture-owned child exited; inspect project fixture logs")
            if (runtime / "endpoint.json").exists():
                endpoint = json.loads((runtime / "endpoint.json").read_text())
                try:
                    async with httpx.AsyncClient(trust_env=False, timeout=.5) as check:
                        if (await check.get(endpoint["origin"] + "/healthz")).status_code == 200:
                            break
                except httpx.HTTPError:
                    pass
            await asyncio.sleep(.05)
        else:
            raise TimeoutError("Fixture backend never became ready")
        client = httpx.AsyncClient(base_url=endpoint["origin"], trust_env=False, timeout=30,
            headers={"Origin": endpoint["origin"]})
        ticket = rpc(ipc_socket, "ticket")
        exchange = await client.post("/api/v1/sessions/exchange", json={"ticket": ticket["ticket"]})
        exchange.raise_for_status()
        client.headers["X-CSRF-Token"] = exchange.json()["csrf"]
        settings = await client.patch("/api/v1/settings", json={"health_interval_s": 2, "connect_timeout_s": 3,
            "probe_timeout_s": 3, "retry_base_s": 1, "retry_max_s": 5})
        settings.raise_for_status()
        group = (await client.post("/api/v1/groups", json={"name": "本机隔离验收"})).json()
        profiles = {}
        specs = [
            ("healthy", "研发节点 · Mac 直连", "MAC_DIRECT", free_port(), "MANAGED", ssh.get_port()),
            ("degraded", "计算节点 · 出口异常", "CLASH_HTTP", proxy_port, "MANAGED", ssh.get_port()),
            ("stopped", "测试节点 · 已关闭", "MAC_DIRECT", free_port(), "MANAGED", ssh.get_port()),
            ("external", "既有连接 · 外部管理", "CLASH_HTTP", proxy_port, "OBSERVED_EXTERNAL", ssh.get_port()),
            ("auth", "认证节点 · 待验证", "CLASH_HTTP", proxy_port, "MANAGED", unknown.get_port()),
        ]
        for key, name, mode, port, management, ssh_port in specs:
            response = await client.post("/api/v1/servers", json={"name": name, "host": "127.0.0.1",
                "ssh_port": ssh_port, "user": "fixture", "mode": mode, "proxy_port": port,
                "remote_proxy_port": free_port(), "health_url": f"https://localhost:{origin_port}/{key}",
                "expected_status": [200], "auto_reconnect": False, "management": management,
                "group_id": group["id"]})
            response.raise_for_status()
            profiles[key] = response.json()
        for key in ("healthy", "degraded", "auth"):
            accepted = await client.post(f"/api/v1/servers/{profiles[key]['id']}/actions/start")
            await wait_operation(client, accepted)
        observed = {key: (await client.get(f"/api/v1/servers/{value['id']}/runtime")).json()
            for key, value in profiles.items()}
        assert observed["healthy"]["state"] == "HEALTHY", observed["healthy"]
        assert observed["healthy"]["tls_completed_ms"] > 0
        assert observed["degraded"]["state"] == "DEGRADED", observed["degraded"]
        assert observed["degraded"]["http_status"] == 503
        assert observed["auth"]["state"] == "AUTH_REQUIRED", observed["auth"]
        metadata = {"origin": endpoint["origin"], "ipc_socket": str(ipc_socket), "packaged_app": args.packaged,
            "packaged_app_path": str(app_path) if args.packaged else None,
            "fixture_socket": str(runtime / "fixture.sock"), "runtime_dir": str(runtime), "data_dir": str(data),
            "profiles": {key: {"id": value["id"], "name": value["name"]} for key, value in profiles.items()},
            "evidence": {"actual_openssh": True, "actual_tinyproxy": True, "verified_tls": True,
                "synthetic_credentials": bool(args.credential_fixture),
                "http_requests": status["requests"], "states": {key: value.get("state") for key, value in observed.items()}}}

        async def control_request(reader, writer):
            try:
                request = json.loads(await asyncio.wait_for(reader.readline(), timeout=3))
                command_name = request.get("command")
                if command_name == "stop":
                    finished.set()
                    result = {"stopping": True}
                elif command_name == "credential-case" and args.credential_fixture:
                    case = request.get("case")
                    if case not in {"READABLE", "MIXED", "OAUTH_ONLY", "MISSING_KEY", "NOT_FOUND", "UNREADABLE",
                                    "INVALID_JSON", "INVALID_KEY", "TOO_LARGE"}:
                        result = {"error": "Unknown synthetic credential case"}
                    else:
                        credential_case(case)
                        result = {"case": case, "synthetic_only": True}
                elif command_name == "upstream":
                    code = request.get("status")
                    if code not in {200, 503}:
                        result = {"error": "Only isolated fixture HTTP 200/503 are supported"}
                    else:
                        status["healthy"] = code
                        result = {"status": code}
                else:
                    result = {"metadata": metadata, "requests": status["requests"],
                              "credential_checks": status["credential_checks"]}
                writer.write(json.dumps(result).encode() + b"\n")
                await writer.drain()
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()

        control = await asyncio.start_unix_server(control_request, path=str(runtime / "fixture.sock"))
        (runtime / "fixture.sock").chmod(0o600)
        private_json(project_path(args.metadata), metadata)
        print(json.dumps({"fixture_ready": True, "metadata": args.metadata, "evidence": metadata["evidence"]}), flush=True)
        await finished.wait()
    finally:
        if control:
            control.close()
            await control.wait_closed()
        if client:
            await client.aclose()
        if backend.poll() is None:
            with contextlib.suppress(OSError, ValueError):
                await asyncio.to_thread(rpc, ipc_socket, "shutdown")
            try:
                await asyncio.to_thread(backend.wait, 10)
            except subprocess.TimeoutExpired:
                backend.terminate()
                await asyncio.to_thread(backend.wait, 5)
        if proxy.poll() is None:
            proxy.terminate()
            await asyncio.to_thread(proxy.wait, 5)
        ssh.close()
        unknown.close()
        await ssh.wait_closed()
        await unknown.wait_closed()
        for connection in connections:
            connection.close()
            with contextlib.suppress(OSError):
                await connection.wait_closed()
        origin.close()
        await origin.wait_closed()
        proxy_log.close()
        backend_log.close()
        print("V2 isolated fixture-owned children and listeners closed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", default=str(ROOT / "var/reports/v2-fixture.json"))
    parser.add_argument("--web-dir", default=str(ROOT / "var/build/web"))
    parser.add_argument("--packaged", action="store_true", help="Run the frozen app-owned host with no developer PATH/runtime")
    parser.add_argument("--app-path", default=str(ROOT / "var/dist/Tunnel Manager.app"),
        help="Select an already-built project-local app for an isolated frozen-host audit")
    parser.add_argument("--credential-fixture", action="store_true",
        help="Enable isolated synthetic auth.json cases; never reads a user's credential file")
    asyncio.run(run(parser.parse_args()))
