"""Independent actual OpenSSH / CONNECT / verified TLS model-test evidence.

Only generated project-local auth files are read. A fixture-only Python prelude
maps one synthetic public DNS answer and trusts the generated fixture CA; the
product helper has no loopback bypass. The real owned reverse-forward socket,
TLS hostname verification, request bytes and provider response parser run.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shlex
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncssh
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tests.integration.test_fault_recovery import action, free_port, runtime

ROOT = Path(__file__).resolve().parents[2]
SENTINEL = "SYNTHETIC-MODEL-KEY-NEVER-A-REAL-CREDENTIAL"
HOST = "api.synthetic.example.com"
PUBLIC_IP = "93.184.216.34"
BASE_URL = "https://" + HOST + "/v1"
MODEL = "synthetic-tiny-model"


def write_auth(directory: Path, document):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "auth.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    return path


def fixture_certificate(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    key_path, ca_path = directory / "synthetic.key", directory / "synthetic.crt"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    ca_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca_path, key_path)
    return ca_path, context


def helper_source(command):
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";")
    lexer.whitespace_split = True
    arguments = list(lexer)
    index = arguments.index("-c")
    assert arguments[index - 2:index] == ["/usr/bin/python3", "-I"]
    return arguments[index + 1]


def fixture_prelude(ca_path, *, private_dns=False, trust_ca=True):
    addresses = private_dns if isinstance(private_dns, list) else ["127.0.0.1"] if private_dns else [PUBLIC_IP]
    return ("import socket, ssl\n"
        "_fixture_real_dns=socket.getaddrinfo\n"
        f"_fixture_addresses={addresses!r}\n"
        "def _fixture_dns(host, port, *args, **kwargs):\n"
        f"    if host == {HOST!r}:\n"
        "        return [(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,port)) for ip in _fixture_addresses]\n"
        "    return _fixture_real_dns(host,port,*args,**kwargs)\n"
        "socket.getaddrinfo=_fixture_dns\n" +
        ("_fixture_real_context=ssl.create_default_context\n"
         f"ssl.create_default_context=lambda *a,**k: _fixture_real_context(cafile={str(ca_path)!r})\n"
         if trust_ca else ""))


@pytest.fixture
async def model_network(live):
    data = live.data_dir.parent
    home = data / "synthetic-model-home"
    codex_home = home / ".codex"
    home.mkdir(mode=0o700)
    write_auth(codex_home, {"OPENAI_API_KEY": SENTINEL})
    (codex_home / "config.toml").write_text(
        f'model = "{MODEL}"\nmodel_provider = "synthetic"\n'
        f'[model_providers.synthetic]\nbase_url = "{BASE_URL}"\nwire_api = "responses"\n')
    (codex_home / "config.toml").chmod(0o600)
    ca_path, tls = fixture_certificate(data)
    state = {"requests": [], "connects": [], "commands": [], "children": [], "connections": [], "stderr": [],
        "status": 200, "body": {"id": "resp_synthetic", "object": "response", "status": "completed",
        "model": MODEL, "output": [{"type": "message", "role": "assistant", "status": "completed",
        "content": [{"type": "output_text", "text": "OK"}]}]}, "content_type": "application/json",
        "private_dns": False, "trust_ca": True, "delay": 0, "helper_calls": 0}

    async def provider_request(reader, writer):
        try:
            header = await reader.readuntil(b"\r\n\r\n")
            length = int(re.search(rb"(?im)^content-length:\s*(\d+)", header)[1])
            body = await reader.readexactly(length)
            state["requests"].append({"header": header, "body": body})
            await asyncio.sleep(state["delay"])
            payload = state["body"]
            encoded = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            status = state["status"]
            writer.write(f"HTTP/1.1 {status} Fixture\r\nContent-Type: {state['content_type']}\r\n"
                f"Content-Length: {len(encoded)}\r\nLocation: https://evil.example.com/leak\r\n"
                "Connection: close\r\n\r\n".encode() + encoded)
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    provider = await asyncio.start_server(provider_request, "127.0.0.1", 0, ssl=tls)
    origin_port = provider.sockets[0].getsockname()[1]

    async def copy_stream(reader, writer):
        try:
            while chunk := await reader.read(8192):
                writer.write(chunk)
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    async def proxy_request(reader, writer):
        origin_writer = None
        try:
            header = await reader.readuntil(b"\r\n\r\n")
            if header.startswith(b"CONNECT "):
                state["connects"].append(header)
                assert header.startswith(f"CONNECT {PUBLIC_IP}:443 ".encode()), header
                assert SENTINEL.encode() not in header
                origin_reader, origin_writer = await asyncio.open_connection("127.0.0.1", origin_port)
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
                await asyncio.gather(copy_stream(reader, origin_writer), copy_stream(origin_reader, writer))
            else:
                # Existing tunnel health checks use HTTP, no auth/model traffic.
                writer.write(b"HTTP/1.1 200 Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            if origin_writer:
                origin_writer.close()
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    proxy = await asyncio.start_server(proxy_request, "127.0.0.1", 0)

    class Server(asyncssh.SSHServer):
        def connection_made(self, connection):
            state["connections"].append(connection)

        def begin_auth(self, username):
            return False

        def server_requested(self, host, port):
            return host == "127.0.0.1" and port >= 1024

    async def command(process):
        state["commands"].append(process.command)
        if "/usr/bin/python3 -I -c " in process.command:
            state["helper_calls"] += 1
            source = helper_source(process.command)
            prelude = fixture_prelude(ca_path, private_dns=state["private_dns"], trust_ca=state["trust_ca"])
            child = await asyncio.create_subprocess_exec("/usr/bin/python3", "-I", "-c", prelude + source,
                cwd=ROOT, env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        elif process.command.startswith("if command -v ss"):
            port = int(re.search(r"sport = :(\d+)", process.command)[1])
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                await writer.wait_closed()
                process.exit(0)
            except OSError:
                process.exit(1)
            return
        elif process.command.startswith("curl "):
            args = shlex.split(process.command)
            child = await asyncio.create_subprocess_exec("/usr/bin/curl", *args[1:],
                env={"PATH": "/usr/bin:/bin"}, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        else:
            process.exit(69)
            return
        state["children"].append(child)
        try:
            out, err = await asyncio.wait_for(child.communicate(), 30)
        except BaseException:
            if child.returncode is None:
                child.kill()
                await child.communicate()
            raise
        assert SENTINEL.encode() not in out and SENTINEL.encode() not in err
        process.stdout.write(out.decode("ascii"))
        state["stderr"].append(err)
        process.stderr.write(err.decode("ascii"))
        process.exit(child.returncode)

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    ssh = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[host_key], server_factory=Server,
        process_factory=command, encoding="utf-8")
    known = live.data_dir / "known_hosts"
    known.write_bytes(f"[127.0.0.1]:{ssh.get_port()} ".encode() + host_key.export_public_key())
    known.chmod(0o600)
    async with httpx.AsyncClient(base_url=live.origin, trust_env=False, cookies=live.client.cookies,
        headers=dict(live.client.headers), timeout=35) as client:
        assert (await client.patch("/api/v1/settings", json={"health_interval_s": 3600,
            "connect_timeout_s": 3, "probe_timeout_s": 2})).status_code == 200
        response = await client.post("/api/v1/servers", json={"name": "isolated model fixture", "host": "127.0.0.1",
            "ssh_port": ssh.get_port(), "user": "synthetic", "mode": "CLASH_HTTP", "auto_reconnect": False,
            "proxy_port": proxy.sockets[0].getsockname()[1], "remote_proxy_port": free_port(),
            "health_url": "http://fixture.invalid/health", "expected_status": [200]})
        assert response.status_code == 201
        server = response.json()
        try:
            yield live, client, server, state, codex_home
        finally:
            await action(client, server, "stop")
            ssh.close()
            for connection in state["connections"]:
                connection.close()
                with contextlib.suppress(OSError):
                    await connection.wait_closed()
            await ssh.wait_closed()
            for listener in (proxy, provider):
                listener.close()
                await listener.wait_closed()
            for child in state["children"]:
                if child.returncode is None:
                    child.kill()
                    await child.communicate()


def model_body(server, **updates):
    return {"source": "REMOTE_CODEX_AUTH_JSON", "consent": True, "base_url": BASE_URL,
        "model": MODEL, "wire_api": "responses", "expected_revision": server["revision"], **updates}


async def run_model(client, server, **updates):
    # Starting a tunnel changes the desired-state profile revision. This models
    # the UI reviewing the current version before an explicit paid request.
    current = (await client.get(f"/api/v1/servers/{server['id']}")).json()
    response = await client.post(f"/api/v1/servers/{server['id']}/model-test",
        json=model_body(current, **updates))
    assert response.status_code == 200, response.text
    assert SENTINEL not in response.text and "evil.example.com" not in response.text
    return response.json()


def assert_no_persistence(live):
    for path in live.data_dir.rglob("*"):
        if path.is_file():
            assert SENTINEL.encode() not in path.read_bytes(), path
    assert SENTINEL.encode() not in live.log_path.read_bytes()


async def test_real_model_call_needs_click_and_existing_owned_channel(model_network):
    live, client, server, state, codex_home = model_network
    stopped = await run_model(client, server)
    assert stopped["state"] == "CHECK_UNAVAILABLE" and not stopped["llm_completion_verified"]
    assert not state["connections"] and not state["helper_calls"] and not state["requests"]
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    initial = await runtime(client, server)
    assert initial["state"] == "HEALTHY" and len(state["connections"]) == 1
    preview = await client.post(f"/api/v1/servers/{server['id']}/model-test/preview",
        json={"source": "REMOTE_CODEX_AUTH_JSON"})
    assert preview.status_code == 200, preview.text
    assert preview.json()["base_url"] == BASE_URL and preview.json()["model"] == MODEL
    assert SENTINEL not in preview.text and not state["requests"]
    denied = await client.post(f"/api/v1/servers/{server['id']}/model-test",
        json=model_body(server, consent=False))
    assert denied.status_code == 403 and not state["requests"]
    result = await run_model(client, server)
    assert result["state"] == "SUCCESS" and result["authentication"] == "VERIFIED", json.dumps({**result, "stderr": [x.decode("ascii", "replace") for x in state["stderr"]]})
    assert result["model_completion"] == "SUCCEEDED" and result["llm_completion_verified"] is True
    assert result["http_status"] == 200 and result["total_ms"] > 0
    assert len(state["requests"]) == len(state["connects"]) == 1
    request = state["requests"][0]
    assert request["header"].startswith(b"POST /v1/responses HTTP/1.1\r\n")
    assert (b"Authorization: Bearer " + SENTINEL.encode()) in request["header"]
    body = json.loads(request["body"])
    assert body["model"] == MODEL and body["stream"] is False
    assert body["input"] == "Reply with OK only." and 1 <= body["max_output_tokens"] <= 128
    assert body["store"] is False
    assert SENTINEL not in json.dumps(body)
    assert (await runtime(client, server))["pid"] == initial["pid"]
    assert len(state["connections"]) == 1
    assert json.loads((codex_home / "auth.json").read_text())["OPENAI_API_KEY"] == SENTINEL
    duplicate = await client.post(f"/api/v1/servers/{server['id']}/model-test",
        json=model_body((await client.get(f"/api/v1/servers/{server['id']}")).json()))
    assert duplicate.status_code == 429 and duplicate.json()["code"] == "MODEL_TEST_COOLDOWN"
    assert len(state["requests"]) == len(state["connects"]) == 1
    assert_no_persistence(live)


@pytest.mark.parametrize("status,body,content_type,expected", [
    (401, {"error": {"message": SENTINEL}}, "application/json", "AUTH_REJECTED"),
    (403, {"error": {"message": SENTINEL}}, "application/json", "PERMISSION_DENIED"),
    (429, {"error": {"message": SENTINEL}}, "application/json", "RATE_LIMITED"),
    (500, {"error": {"message": SENTINEL}}, "application/json", "UPSTREAM_ERROR"),
    (302, {"error": {"message": SENTINEL}}, "application/json", "UPSTREAM_ERROR"),
    (200, b"<html>success page</html>", "text/html", "INVALID_RESPONSE"),
    (200, {"id": "resp_empty", "object": "response", "model": MODEL,
        "status": "completed", "output": []}, "application/json", "EMPTY_OUTPUT"),
    (200, {"id": "resp_incomplete", "object": "response", "model": MODEL,
        "status": "incomplete", "output": []}, "application/json", "INCOMPLETE"),
    (200, b"x" * 131073, "application/json", "INVALID_RESPONSE"),
    (200, {"id": "resp_opaque", "object": "response", "model": MODEL, "status": "completed", "output": [
        {"type": "message", "role": "assistant", "status": "completed", "content": [
            {"type": "output_text", "text": SENTINEL}]}]}, "application/json", "SUCCESS"),
], ids=["unauthorized", "forbidden", "rate-limit", "server-error", "redirect", "html", "empty", "incomplete", "oversized", "output-opaque"])
async def test_real_failures_no_retry_no_false_success_or_error_body_leak(model_network, status, body, content_type, expected):
    live, client, server, state, _ = model_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    initial = await runtime(client, server)
    state.update(status=status, body=body, content_type=content_type)
    result = await run_model(client, server)
    assert result["state"] == expected
    assert result["llm_completion_verified"] is (expected == "SUCCESS")
    assert (result["model_completion"] == "SUCCEEDED") is (expected == "SUCCESS")
    assert len(state["requests"]) == len(state["connects"]) == 1
    assert (await runtime(client, server))["pid"] == initial["pid"]
    assert SENTINEL not in json.dumps((await client.get("/api/v1/activity")).json())
    assert_no_persistence(live)


@pytest.mark.parametrize("text,finish,expected", [("OK", "stop", "SUCCESS"),
    ("", "stop", "EMPTY_OUTPUT"), ("partial", "length", "INCOMPLETE")])
async def test_real_chat_completion_does_not_accept_empty_or_truncated_output(model_network, text, finish, expected):
    live, client, server, state, _ = model_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    state["body"] = {"id": "chat_synthetic", "object": "chat.completion", "model": MODEL,
        "choices": [{"index": 0, "finish_reason": finish,
                     "message": {"role": "assistant", "content": text}}]}
    result = await run_model(client, server, wire_api="chat")
    assert result["state"] == expected
    assert result["llm_completion_verified"] is (expected == "SUCCESS")
    assert state["requests"][-1]["header"].startswith(b"POST /v1/chat/completions HTTP/1.1\r\n")
    assert len(state["requests"]) == 1 and len(state["connections"]) == 1
    assert_no_persistence(live)


@pytest.mark.parametrize("change,expected,requests", [
    ({"private_dns": True}, "CHECK_UNAVAILABLE", 0),
    ({"private_dns": [PUBLIC_IP, "127.0.0.1"]}, "CHECK_UNAVAILABLE", 0),
    ({"trust_ca": False}, "TLS_ERROR", 0),
])
async def test_real_dns_private_answer_and_untrusted_tls_never_receive_key(model_network, change, expected, requests):
    live, client, server, state, _ = model_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    state.update(change)
    result = await run_model(client, server)
    assert result["state"] == expected and not result["llm_completion_verified"]
    assert len(state["requests"]) == requests
    assert_no_persistence(live)


async def test_real_provider_timeout_is_failure_with_no_automatic_paid_retry(model_network):
    live, client, server, state, _ = model_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    state["delay"] = 11
    result = await run_model(client, server)
    assert result["state"] == "TIMEOUT" and not result["llm_completion_verified"]
    assert len(state["requests"]) == len(state["connects"]) == 1
    assert_no_persistence(live)


@pytest.mark.parametrize("kind", ["oauth", "world-readable", "missing"])
async def test_real_unsafe_or_unsupported_credential_never_contacts_provider(model_network, kind):
    live, client, server, state, codex_home = model_network
    auth = codex_home / "auth.json"
    if kind == "oauth":
        write_auth(codex_home, {"tokens": {"access_token": SENTINEL}, "auth_mode": "chatgpt"})
    elif kind == "world-readable":
        auth.chmod(0o644)
    else:
        auth.unlink()
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    result = await run_model(client, server)
    assert result["state"] == "CREDENTIAL_UNAVAILABLE" and not result["llm_completion_verified"]
    assert not state["requests"] and not state["connects"]
    assert_no_persistence(live)


async def test_real_missing_mux_and_stale_revision_never_fall_back_or_bill(model_network):
    live, client, server, state, _ = model_network
    assert (await action(client, server, "start"))["status"] == "SUCCEEDED"
    initial = await runtime(client, server)
    current = (await client.get(f"/api/v1/servers/{server['id']}")).json()
    response = await client.post(f"/api/v1/servers/{server['id']}/model-test",
        json=model_body(current, expected_revision=current["revision"] + 1))
    assert response.status_code == 409
    assert not state["requests"] and not state["helper_calls"]
    socket_path = ROOT / ".run/s" / initial["run_id"][:10]
    assert socket_path.is_socket()
    socket_path.unlink()
    result = await run_model(client, server)
    assert result["state"] == "CHECK_UNAVAILABLE" and not result["llm_completion_verified"]
    assert not state["requests"] and not state["helper_calls"]
    assert len(state["connections"]) == 1
    assert_no_persistence(live)
