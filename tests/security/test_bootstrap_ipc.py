import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest


def ipc_call(path: Path, request: object):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(path))
        client.sendall(json.dumps(request).encode() + b"\n")
        output = client.recv(4096)
        return json.loads(output) if output else None


@pytest.fixture
def isolated_bootstrap(tmp_path):
    project = Path(__file__).resolve().parents[2]
    runtime = project / ".run" / ("sec-" + uuid.uuid4().hex[:8])
    runtime.mkdir(mode=0o700)
    control = runtime / "control.sock"
    assert len(os.fsencode(control)) <= 100
    log_path = tmp_path / "bootstrap.stderr"
    environment = os.environ.copy()
    environment.update({"PYTHONPATH": str(project / "apps" / "backend"), "TMPDIR": str(tmp_path),
                        "PYTHONDONTWRITEBYTECODE": "1"})
    with log_path.open("w") as stream:
        process = subprocess.Popen([
            sys.executable, "-m", "app.bootstrap", "--data-dir", str(tmp_path / "data"),
            "--runtime-dir", str(runtime), "--port", "0",
        ], cwd=project, env=environment, stdin=subprocess.DEVNULL, stdout=stream, stderr=stream)
        try:
            deadline = time.monotonic() + 5
            while not control.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert control.exists(), "Isolated backend did not create its private IPC socket"
            yield process, runtime, log_path
        finally:
            if process.poll() is None and control.exists():
                ipc_call(control, {"command": "shutdown"})
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
            for child in runtime.iterdir():
                child.unlink()
            runtime.rmdir()


@pytest.mark.parametrize("invalid", [None, [], "ticket", 123])
def test_malformed_ipc_shape_rejected_without_exception(isolated_bootstrap, invalid):
    process, runtime, log_path = isolated_bootstrap
    ipc_call(runtime / "control.sock", invalid)
    status = ipc_call(runtime / "control.sock", {"command": "status"})
    assert status["alive"] is True and status["pid"] == process.pid
    time.sleep(0.02)
    assert "AttributeError" not in log_path.read_text()


def test_bootstrap_ticket_not_written_to_endpoint_or_log(isolated_bootstrap):
    _, runtime, log_path = isolated_bootstrap
    response = ipc_call(runtime / "control.sock", {"command": "ticket"})
    ticket = response["ticket"]
    assert len(ticket) >= 32
    assert ticket not in (runtime / "endpoint.json").read_text()
    assert ticket not in log_path.read_text()
    for path in (runtime, runtime / "endpoint.json", runtime / "control.sock"):
        assert path.stat().st_mode & 0o077 == 0


def test_pending_ticket_limit_rejects_cleanly_without_handler_traceback(isolated_bootstrap):
    process, runtime, log_path = isolated_bootstrap
    for _ in range(64):
        assert ipc_call(runtime / "control.sock", {"command": "ticket"})["ticket"]
    limited = ipc_call(runtime / "control.sock", {"command": "ticket"})
    assert isinstance(limited, dict) and limited.get("error"), "Capacity rejection must return a bounded protocol error"
    assert ipc_call(runtime / "control.sock", {"command": "status"})["pid"] == process.pid
    time.sleep(0.02)
    assert "RuntimeError" not in log_path.read_text()


def test_deep_ipc_json_rejects_without_parser_traceback(isolated_bootstrap):
    process, runtime, log_path = isolated_bootstrap
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(runtime / "control.sock"))
        client.sendall(b"[" * 1000 + b"0" + b"]" * 1000 + b"\n")
        client.recv(4096)
    assert ipc_call(runtime / "control.sock", {"command": "status"})["pid"] == process.pid
    time.sleep(0.02)
    assert "RecursionError" not in log_path.read_text()
