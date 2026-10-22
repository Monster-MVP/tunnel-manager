"""Real native host/frozen backend lifecycle test using isolated project paths."""

from __future__ import annotations

import json
import os
import pathlib
import signal
import socket
import subprocess
import time
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
APP = ROOT / "var/dist/Tunnel Manager.app"
EXECUTABLE = APP / "Contents/MacOS/TunnelManager"


def rpc(path: pathlib.Path, command: str) -> dict:
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(2)
        channel.connect(str(path))
        channel.sendall((json.dumps({"command": command}) + "\n").encode())
        return json.loads(channel.recv(4096))


def await_ticket(path: pathlib.Path, host: subprocess.Popen) -> dict:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if host.poll() is not None:
            raise AssertionError(f"Native host exited with {host.returncode}")
        try:
            ticket = rpc(path, "ticket")
            if ticket.get("ticket"):
                return ticket
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise AssertionError("Frozen backend did not become ready")


def test_native_lifecycle() -> dict:
    tag = uuid.uuid4().hex[:8]
    runtime = ROOT / ".run" / tag
    data = ROOT / "var/data" / f"native-{tag}"
    host = subprocess.Popen(
        [str(EXECUTABLE), "--service-host", "--runtime-dir", str(runtime), "--data-dir", str(data)]
    )
    events = []
    try:
        socket_path = runtime / "host.sock"
        ticket = await_ticket(socket_path, host)
        port = ticket["port"]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3) as response:
            assert json.load(response)["alive"]
        events.append("native_frozen_backend_loopback_health")
        assert rpc(socket_path, "status")["backend_alive"]
        duplicate = subprocess.run(
            [str(EXECUTABLE), "--service-host", "--runtime-dir", str(runtime), "--data-dir", str(data)],
            timeout=5,
            check=False,
        )
        assert duplicate.returncode == 78, "Duplicate host did not fail under singleton lock"
        assert rpc(socket_path, "status")["pid"] == host.pid
        events.append("repeated_service_launch_singleton")
        endpoint = json.loads((runtime / "endpoint.json").read_text())
        first_pid = endpoint["pid"]
        # PID comes from the service under test and is verified as its direct child and private group.
        assert subprocess.check_output(
            ["/bin/ps", "-o", "ppid=", "-p", str(first_pid)], text=True
        ).strip() == str(host.pid)
        assert os.getpgid(first_pid) == first_pid
        os.kill(first_pid, signal.SIGKILL)
        deadline = time.monotonic() + 15
        recovered = None
        while time.monotonic() < deadline:
            try:
                current = json.loads((runtime / "endpoint.json").read_text())
                if current["pid"] != first_pid:
                    recovered = await_ticket(socket_path, host)
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.1)
        assert recovered, "Backend crash was not recovered"
        events.append("private_process_group_backend_crash_recovery")
        assert rpc(socket_path, "shutdown")["stopping"]
        host.wait(timeout=10)
        assert host.returncode == 0
        assert not (runtime / "host.sock").exists()
        assert not (runtime / "control.sock").exists()
        events.append("owned_service_shutdown_cleans_ipc")
        # Parent death while backend is loading must not strand the frozen service.
        host = subprocess.Popen(
            [str(EXECUTABLE), "--service-host", "--runtime-dir", str(runtime), "--data-dir", str(data)]
        )
        ticket = await_ticket(runtime / "host.sock", host)
        orphan_pid = json.loads((runtime / "endpoint.json").read_text())["pid"]
        assert subprocess.check_output(
            ["/bin/ps", "-o", "ppid=", "-p", str(orphan_pid)], text=True
        ).strip() == str(host.pid)
        os.kill(host.pid, signal.SIGKILL)
        host.wait(timeout=5)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and (runtime / "control.sock").exists():
            time.sleep(0.1)
        assert not (runtime / "control.sock").exists(), "Frozen backend survived host death"
        # A stale host socket is removed under the singleton lock when the next host starts.
        host = subprocess.Popen(
            [str(EXECUTABLE), "--service-host", "--runtime-dir", str(runtime), "--data-dir", str(data)]
        )
        await_ticket(runtime / "host.sock", host)
        assert rpc(runtime / "host.sock", "shutdown")["stopping"]
        host.wait(timeout=10)
        events.append("host_crash_backend_parent_guard_and_stale_ipc_recovery")
    finally:
        if host.poll() is None:
            try:
                rpc(runtime / "host.sock", "shutdown")
                host.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                host.terminate()
                host.wait(timeout=5)
    return {"passed": events, "runtime": str(runtime.relative_to(ROOT))}


if __name__ == "__main__":
    result = test_native_lifecycle()
    output = ROOT / "var/reports/macos-native-smoke.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
