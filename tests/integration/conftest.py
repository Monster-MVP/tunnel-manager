from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def project_data_dir():
    path = ROOT / "var" / "tmp" / "reliability" / uuid4().hex
    path.mkdir(parents=True, mode=0o700)
    return path


class LiveBackend:
    def __init__(self, data_dir: Path, web_dir: Path | None = None):
        assert data_dir.is_relative_to(ROOT)
        self.data_dir = data_dir
        self.runtime_dir = ROOT / ".run" / ("q6-" + uuid4().hex[:6])
        self.runtime_dir.mkdir(parents=True, mode=0o700)
        self.log_path = data_dir.parent / "backend.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log = self.log_path.open("ab")
        argv = [str(ROOT / ".venv/bin/python"), "-m", "app.bootstrap", "--data-dir", str(data_dir),
                "--runtime-dir", str(self.runtime_dir), "--port", "0"]
        if web_dir:
            argv.extend(["--web-dir", str(web_dir)])
        environment = os.environ.copy()
        environment.update(PYTHONPATH=str(ROOT / "apps/backend"), TMPDIR=str(ROOT / "var/tmp"),
                           PYTHONDONTWRITEBYTECODE="1")
        self.process = subprocess.Popen(argv, cwd=ROOT, env=environment, stdout=self.log, stderr=self.log,
                                        start_new_session=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"Isolated backend exited: {self.log_path.read_text()}")
            if (self.runtime_dir / "endpoint.json").exists():
                self.endpoint = json.loads((self.runtime_dir / "endpoint.json").read_text())
                self.origin = self.endpoint["origin"]
                try:
                    if httpx.get(self.origin + "/healthz", timeout=.5, trust_env=False).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
            time.sleep(.05)
        else:
            self.close()
            raise AssertionError("Isolated backend never became healthy")
        self.client = httpx.Client(base_url=self.origin, timeout=15, trust_env=False, headers={"Origin": self.origin})
        exchange = self.client.post("/api/v1/sessions/exchange", json={"ticket": self.ipc("ticket")["ticket"]})
        assert exchange.status_code == 200
        self.client.headers["X-CSRF-Token"] = exchange.json()["csrf"]

    def ipc(self, command: str) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(str(self.runtime_dir / "control.sock"))
            connection.sendall(json.dumps({"command": command}).encode() + b"\n")
            return json.loads(connection.recv(4096))

    def close(self):
        if hasattr(self, "client"):
            self.client.close()
        if self.process.poll() is None:
            self.ipc("shutdown")
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # This exact handle created the isolated child; no external PID is targeted.
                self.process.terminate()
                self.process.wait(timeout=5)
        self.log.close()


@pytest.fixture
def live(project_data_dir):
    instance = LiveBackend(project_data_dir / "data")
    try:
        yield instance
    finally:
        instance.close()


@pytest.fixture
def backend_factory():
    return LiveBackend
