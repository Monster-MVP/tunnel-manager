"""Serve an isolated frozen App with real SSH, CONNECT and synthetic TLS models.

The independent reliability fixture owns the fake provider and generated keys.
Its test-only DNS/CA mapping is deliberately outside the product helper. Nothing
in this command connects to a production host or reads a personal credential.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib.util
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.integration.conftest import LiveBackend
from tests.integration.test_fault_recovery import action, free_port

spec = importlib.util.spec_from_file_location("model_network_audit", ROOT / "tests/v2-reliability/test_codex_model_test_live.py")
network_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network_module)


class PackagedBackend(LiveBackend):
    def __init__(self, data: Path, app: Path):
        data.mkdir(parents=True, mode=0o700)
        self.data_dir = data
        self.runtime_dir = ROOT / ".run" / ("mu-" + uuid4().hex[:6])
        self.runtime_dir.mkdir(mode=0o700)
        self.log_path = data.parent / "backend.log"
        self.log = self.log_path.open("ab")
        self.process = subprocess.Popen([
            str(app / "Contents/MacOS/TunnelManager"), "--service-host", "--data-dir", str(data),
            "--runtime-dir", str(self.runtime_dir),
        ], cwd=ROOT, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": str(ROOT / "var/tmp")},
            stdout=self.log, stderr=self.log, start_new_session=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("Isolated frozen host exited; inspect fixture log")
            endpoint = self.runtime_dir / "endpoint.json"
            if endpoint.exists():
                self.endpoint = json.loads(endpoint.read_text())
                self.origin = self.endpoint["origin"]
                try:
                    if httpx.get(self.origin + "/healthz", timeout=.5, trust_env=False).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
            time.sleep(.05)
        else:
            raise RuntimeError("Isolated frozen host did not become ready")
        self.client = httpx.Client(base_url=self.origin, trust_env=False, timeout=15, headers={"Origin": self.origin})
        response = self.client.post("/api/v1/sessions/exchange", json={"ticket": self.ipc("ticket")["ticket"]})
        response.raise_for_status()
        self.client.headers["X-CSRF-Token"] = response.json()["csrf"]

    def ipc(self, command: str) -> dict:
        with socket.socket(socket.AF_UNIX) as channel:
            channel.settimeout(4)
            channel.connect(str(self.runtime_dir / "host.sock"))
            channel.sendall(json.dumps({"command": command}).encode() + b"\n")
            return json.loads(channel.recv(8192))


def project_path(value: str) -> Path:
    path = Path(value).absolute()
    if not path.is_relative_to(ROOT) or path.resolve() != path:
        raise ValueError("Project-local non-symlink path required")
    return path


def write_private(path: Path, value: dict):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    path.chmod(0o600)


async def run(args) -> None:
    app = project_path(args.app_path)
    metadata_path = project_path(args.metadata)
    if metadata_path.exists():
        raise FileExistsError("Preserve prior fixture metadata")
    data = ROOT / "var/tmp/model-ui" / uuid4().hex / "data"
    live = await asyncio.to_thread(PackagedBackend, data, app)
    generator = network_module.model_network.__wrapped__(live)
    control = None
    finished = asyncio.Event()
    try:
        _, client, server, state, codex_home = await anext(generator)
        started = await action(client, server, "start")
        if started["status"] != "SUCCEEDED":
            raise RuntimeError("Synthetic tunnel did not start")
        profiles = {"healthy": {"id": server["id"], "name": server["name"]}}
        source_fields = {key: server[key] for key in (
            "host", "ssh_port", "user", "mode", "proxy_port", "health_url", "expected_status")}
        async def new_profile(name, management="MANAGED", start=False):
            response = await client.post("/api/v1/servers", json={**source_fields,
                "name": name, "remote_proxy_port": free_port(), "auto_reconnect": False, "management": management})
            response.raise_for_status()
            profile = response.json()
            if start and (await action(client, profile, "start"))["status"] != "SUCCEEDED":
                raise RuntimeError("Isolated model profile failed to start")
            return {"id": profile["id"], "name": profile["name"]}
        profiles["stopped"] = await new_profile("模型测试 · 已关闭")
        profiles["external"] = await new_profile("模型测试 · 外部观察", "OBSERVED_EXTERNAL")
        metadata = {"origin": live.origin, "ipc_socket": str(live.runtime_dir / "host.sock"),
            "fixture_socket": str(live.runtime_dir / "fixture.sock"), "packaged_app": str(app),
            "profiles": profiles, "evidence": {"actual_openssh": True, "actual_reverse_proxy": True,
                "actual_tls_provider": True, "synthetic_credentials": True, "fixture_only_dns_ca_mapping": True,
                "production_services_controlled": False, "personal_credentials_read": False,
                "genuine_provider_verified": False}}

        async def handle(reader, writer):
            try:
                request = json.loads(await asyncio.wait_for(reader.readline(), 4))
                command = request.get("command")
                if command == "stop":
                    result = {"stopping": True}
                    finished.set()
                elif command == "case":
                    case = request.get("case")
                    allowed = {"responses", "chat", "auth", "permission", "rate", "model", "html", "empty", "incomplete", "credential", "tls", "dns"}
                    if case not in allowed:
                        raise ValueError("Unknown isolated case")
                    state.update(status=200, content_type="application/json", private_dns=False, trust_ca=True)
                    network_module.write_auth(codex_home, {"OPENAI_API_KEY": network_module.SENTINEL})
                    state["body"] = {"id": "resp_synthetic", "object": "response", "model": network_module.MODEL,
                        "status": "completed", "output": [{"type": "message", "role": "assistant", "status": "completed",
                            "content": [{"type": "output_text", "text": "OK"}]}]}
                    if case == "chat":
                        state["body"] = {"id": "chat_synthetic", "object": "chat.completion", "model": network_module.MODEL,
                            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "OK"}}]}
                    elif case in {"auth", "permission", "rate", "model"}:
                        state["status"] = {"auth": 401, "permission": 403, "rate": 429, "model": 404}[case]
                        state["body"] = {"error": {"code": "model_not_found" if case == "model" else "test_failure", "message": network_module.SENTINEL}}
                    elif case == "html":
                        state.update(body=b"<html>not a model result</html>", content_type="text/html")
                    elif case == "empty":
                        state["body"]["output"] = []
                    elif case == "incomplete":
                        state["body"]["status"] = "incomplete"
                    elif case == "credential":
                        (codex_home / "auth.json").chmod(0o644)
                    elif case == "tls":
                        state["trust_ca"] = False
                    elif case == "dns":
                        state["private_dns"] = True
                    profile = await new_profile("模型验收 · " + case, start=True)
                    result = {"case": case, "profile": profile, "synthetic_only": True,
                        "requests": len(state["requests"]), "helper_calls": state["helper_calls"]}
                else:
                    result = {"requests": len(state["requests"]), "helper_calls": state["helper_calls"],
                        "connects": len(state["connects"]), "ssh_connections": len(state["connections"])}
                writer.write(json.dumps(result, ensure_ascii=False).encode() + b"\n")
                await writer.drain()
            except (ValueError, OSError, TimeoutError):
                writer.write(b'{"error":"Isolated fixture control failed"}\n')
                await writer.drain()
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()

        control = await asyncio.start_unix_server(handle, path=str(live.runtime_dir / "fixture.sock"))
        (live.runtime_dir / "fixture.sock").chmod(0o600)
        write_private(metadata_path, metadata)
        print(json.dumps({"fixture_ready": True, "metadata": str(metadata_path), "evidence": metadata["evidence"]}), flush=True)
        await finished.wait()
    finally:
        if control:
            control.close()
            await control.wait_closed()
        await generator.aclose()
        await asyncio.to_thread(live.close)
        print("Isolated model fixture children closed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-path", required=True)
    parser.add_argument("--metadata", required=True)
    asyncio.run(run(parser.parse_args()))
