import importlib.util
import json
import plistlib
import re
import subprocess
import time
import uuid
from pathlib import Path

import httpx
import pytest
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

from tests.app_paths import app_bundle_path
from tests.security.test_bootstrap_ipc import ipc_call

PROJECT = Path(__file__).resolve().parents[2]
APP = app_bundle_path()


@pytest.fixture
def packaged_api(tmp_path):
    executable = APP / "Contents/Resources/backend/tunnel-backend/tunnel-backend"
    assert executable.is_file(), "Release candidate backend is not available"
    runtime = PROJECT / ".run" / ("s3-" + uuid.uuid4().hex[:8])
    runtime.mkdir(mode=0o700)
    control = runtime / "control.sock"
    log = tmp_path / "packaged-backend.log"
    with log.open("w") as output:
        process = subprocess.Popen([
            str(executable), "--data-dir", str(tmp_path / "data"), "--runtime-dir", str(runtime),
            "--web-dir", str(APP / "Contents/Resources/web"), "--port", "0",
        ], cwd=PROJECT, env={"PATH": "/usr/bin:/bin", "TMPDIR": str(tmp_path)},
            stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        try:
            deadline = time.monotonic() + 10
            while not control.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert control.exists(), "Packaged backend failed to create IPC; inspect isolated packaged-backend.log"
            endpoint = json.loads((runtime / "endpoint.json").read_text())
            assert endpoint["pid"] == process.pid
            with httpx.Client(base_url=endpoint["origin"], timeout=3, trust_env=False) as client:
                yield client, process, runtime, log
        finally:
            if process.poll() is None and control.exists():
                ipc_call(control, {"command": "shutdown"})
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
            for path in runtime.iterdir():
                path.unlink()
            runtime.rmdir()


def test_release_candidate_executable_signature_and_manifest():
    assert APP.is_dir(), "Release candidate bundle is unavailable"
    result = subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(APP)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    storage = json.loads((APP / "Contents/Resources/storage.json").read_text())
    manifest = json.loads((APP / "Contents/Resources/install-manifest.json").read_text())
    assert storage["project_root"] == str(PROJECT) and storage["volume_uuid"]
    assert manifest["owner"] == "Tunnel Manager" and manifest["project_root"] == str(PROJECT)
    for path in APP.rglob("*"):
        if path.is_symlink():
            assert path.resolve().is_relative_to(APP), "Bundle symlink escapes release candidate"
        assert path.name not in {"id_rsa", "id_ed25519", "tinyproxy-autodl.conf", ".env"}


def test_release_launch_registration_is_only_app_owned():
    agents = APP / "Contents/Library/LaunchAgents"
    files = list(agents.glob("*.plist"))
    assert len(files) == 1
    value = plistlib.loads(files[0].read_bytes())
    assert value["Label"] == "com.tunnelmanager.service"
    assert value["BundleProgram"] == "Contents/MacOS/TunnelManager"
    assert value["ProgramArguments"] == ["TunnelManager", "--service-host"]
    assert "com.example.external-ssh" not in json.dumps(value)


def test_tinyproxy_has_no_homebrew_runtime_dependency():
    binary = APP / "Contents/Resources/tinyproxy"
    result = subprocess.run(["/usr/bin/otool", "-L", str(binary)], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    dependencies = [line.strip().split(" (", 1)[0] for line in result.stdout.splitlines()[1:]]
    assert dependencies
    assert all(path.startswith(("/usr/lib/", "/System/Library/", "@")) for path in dependencies)
    assert not any("homebrew" in path for path in dependencies)


def test_packaged_backend_auth_csrf_export_and_static_origin(packaged_api):
    client, process, runtime, log = packaged_api
    assert client.get("/healthz").json() == {"alive": True}
    assert client.get("/api/v1/servers").status_code == 401
    assert client.get("/", headers={"Host": "attacker.example"}).status_code == 403
    bootstrap = ipc_call(runtime / "control.sock", {"command": "ticket"})
    ticket = bootstrap["ticket"]
    response = client.post("/api/v1/sessions/exchange", json={"ticket": ticket})
    assert response.status_code == 200
    assert client.post("/api/v1/sessions/exchange", json={"ticket": ticket}).status_code == 401
    client.headers.update({"Origin": str(client.base_url).rstrip("/"), "X-CSRF-Token": response.json()["csrf"]})
    assert client.post("/api/v1/groups", json={"name": "bad"}, headers={"X-CSRF-Token": b"\xe9"}).status_code == 401
    profile = client.post("/api/v1/servers", json={
        "name": "packaged isolated", "host": "bundle-private.example.test", "user": "bundle-user",
        "ssh_alias": "bundle-alias", "health_url": "https://bundle-probe.example.test/private-path/", "mode": "DISABLED",
    })
    assert profile.status_code == 201
    exported = client.post("/api/v1/configuration/export", json={}).json()
    artifact = client.get(exported["download_url"])
    assert artifact.status_code == 200
    for sensitive in ("bundle-private", "bundle-user", "bundle-alias", "bundle-probe", "private-path"):
        assert sensitive not in artifact.text
    static = client.get("/")
    assert static.status_code == 200 and "script" in static.text
    assert "frame-ancestors 'none'" in static.headers["content-security-policy"]
    assert process.poll() is None
    assert ticket not in (runtime / "endpoint.json").read_text()
    assert ticket not in log.read_text()
    assert runtime.stat().st_mode & 0o077 == 0
    assert (runtime / "endpoint.json").stat().st_mode & 0o077 == 0


def test_packaged_backend_external_controls_remain_blocked(packaged_api):
    client, _, runtime, _ = packaged_api
    ticket = ipc_call(runtime / "control.sock", {"command": "ticket"})["ticket"]
    response = client.post("/api/v1/sessions/exchange", json={"ticket": ticket})
    client.headers.update({"Origin": str(client.base_url).rstrip("/"), "X-CSRF-Token": response.json()["csrf"]})
    profile = client.post("/api/v1/servers", json={
        "name": "external synthetic", "host": "example.test", "user": "tester", "management": "OBSERVED_EXTERNAL",
    }).json()
    for action in ("start", "stop", "restart"):
        assert client.post(f"/api/v1/servers/{profile['id']}/actions/{action}").status_code == 403
    assert client.post("/api/v1/migrations/unknown/execute").status_code == 403


def test_packaged_websocket_closes_malformed_and_revoked_sessions(packaged_api):
    client, _, runtime, _ = packaged_api
    ticket = ipc_call(runtime / "control.sock", {"command": "ticket"})["ticket"]
    session = client.post("/api/v1/sessions/exchange", json={"ticket": ticket})
    origin = str(client.base_url).rstrip("/")
    client.headers.update({"Origin": origin, "X-CSRF-Token": session.json()["csrf"]})
    cookie = f"tm_session={client.cookies.get('tm_session')}"
    uri = origin.replace("http://", "ws://", 1) + "/api/v1/ws"

    for invalid, revoke in (({"type": []}, False), ({"type": "ping"}, True)):
        ws_ticket = client.post("/api/v1/ws-tickets").json()["ticket"]
        with connect(uri, origin=origin, additional_headers={"Cookie": cookie}, open_timeout=3, proxy=None) as websocket:
            websocket.send(json.dumps({"type": "authenticate", "ticket": ws_ticket}))
            assert json.loads(websocket.recv(timeout=3))["type"] == "snapshot"
            if revoke:
                revoked = client.delete("/api/v1/sessions/current")
                assert revoked.status_code == 200 and revoked.json()["status"] == "REVOKED"
            websocket.send(json.dumps(invalid))
            with pytest.raises(ConnectionClosed) as error:
                websocket.recv(timeout=3)
            assert error.value.rcvd.code == 1008


def test_packaging_delete_rejects_symlink_and_missing_manifest(tmp_path):
    spec = importlib.util.spec_from_file_location("safe_paths_security", PROJECT / "packaging/macos/safe_paths.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "keep").write_text("sentinel")
    link = tmp_path / "link"
    link.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError):
        module.remove(link / "keep")
    assert (actual / "keep").read_text() == "sentinel"
    owned_name_only = tmp_path / "Tunnel Manager.app"
    owned_name_only.mkdir()
    with pytest.raises((ValueError, FileNotFoundError)):
        module.remove(owned_name_only)
    assert owned_name_only.is_dir()


def test_no_broad_process_kill_or_ssh_trust_bypass_in_release_sources():
    paths = [PROJECT / "apps/backend/app/tunnels/manager.py", PROJECT / "apps/backend/app/proxies/manager.py",
             PROJECT / "apps/macos/TunnelManagerApp.swift", PROJECT / "scripts/macos/install.sh",
             PROJECT / "scripts/macos/uninstall.sh"]
    for path in paths:
        text = path.read_text()
        assert re.search(r"\b(pkill|killall)\s+(ssh|codex)\b", text) is None
        assert "StrictHostKeyChecking=no" not in text
        assert "StrictHostKeyChecking no" not in text
