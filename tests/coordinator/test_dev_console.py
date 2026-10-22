import importlib.util
import json
import socket
import threading
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("open_dev_console", Path(__file__).resolve().parents[2] / "scripts/open_dev_console.py")
console = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(console)


def runtime_fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(console, "ROOT", tmp_path)
    runtime = tmp_path / ".run/dev"
    runtime.mkdir(parents=True, mode=0o700)
    # macOS Unix socket paths are short; use a project-local short path.
    return runtime


def test_development_console_rejects_app_runtime_and_escaping_path(tmp_path, monkeypatch):
    monkeypatch.setattr(console, "ROOT", tmp_path)
    for candidate in (tmp_path / ".run/app", tmp_path / ".run", tmp_path.parent / "outside"):
        with pytest.raises(ValueError):
            console.development_socket(candidate)


def test_development_console_rejects_symlink_and_nonprivate_runtime(tmp_path, monkeypatch):
    runtime = runtime_fixture(tmp_path, monkeypatch)
    runtime.chmod(0o755)
    with pytest.raises(ValueError, match="private"):
        console.development_socket(runtime)
    runtime.chmod(0o700)
    (runtime.parent / "alias").symlink_to(runtime, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        console.development_socket(runtime.parent / "alias")


@pytest.mark.parametrize("reply,valid", [
    ({"port": 18555, "ticket": "SYNTHETIC-ONE-TIME-TICKET-ONLY"}, True),
    ({"port": True, "ticket": "SYNTHETIC-ONE-TIME-TICKET-ONLY"}, False),
    ({"port": 18555, "ticket": "invalid\nsecret"}, False),
    ({"error": "BACKEND_UNAVAILABLE"}, False),
    ([], False),
    (None, False),
])
def test_development_console_uses_real_private_ipc(tmp_path, monkeypatch, reply, valid):
    runtime = runtime_fixture(tmp_path, monkeypatch)
    path = runtime / "control.sock"
    # pytest's long per-test names exceed macOS sun_path; shorten only this
    # isolated temporary runtime, preserving the same path-validation logic.
    monkeypatch.setattr(console, "development_socket", lambda _runtime: path)
    if len(str(path).encode()) > 100:
        path = tmp_path.parents[1] / ("dc-" + str(tmp_path.stat().st_ino))
    observed = []
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen(1)

        def handle():
            connection, _ = listener.accept()
            with connection:
                observed.append(connection.recv(2048))
                connection.sendall(json.dumps(reply).encode() + b"\n")

        thread = threading.Thread(target=handle)
        thread.start()
        try:
            if valid:
                assert console.bootstrap_url(runtime) == "http://127.0.0.1:18555/#ticket=SYNTHETIC-ONE-TIME-TICKET-ONLY"
            else:
                with pytest.raises((TypeError, ValueError)):
                    console.bootstrap_url(runtime)
        finally:
            thread.join(timeout=5)
            path.unlink(missing_ok=True)
    assert observed == [b'{"command":"ticket"}\n']
