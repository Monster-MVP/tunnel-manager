"""Independent V2 final-bundle checks; intentionally fail against the old V1 app."""

import json
import plistlib
from pathlib import Path

from tests.app_paths import app_bundle_path
from tests.security.test_bootstrap_ipc import ipc_call

pytest_plugins = ["tests.security.test_release_candidate"]

PROJECT = Path(__file__).resolve().parents[2]
APP = app_bundle_path()


def authenticate(client, runtime):
    response = client.post("/api/v1/sessions/exchange", json={"ticket": ipc_call(runtime / "control.sock", {"command": "ticket"})["ticket"]})
    assert response.status_code == 200
    client.headers.update({"Origin": str(client.base_url).rstrip("/"), "X-CSRF-Token": response.json()["csrf"]})


def test_final_bundle_declares_v2_and_contains_exact_current_static_build():
    info = plistlib.loads((APP / "Contents/Info.plist").read_bytes())
    assert info["CFBundleShortVersionString"] == "2.0.0"
    manifest = json.loads((APP / "Contents/Resources/install-manifest.json").read_text())
    assert manifest["version"] == "2.0.0"
    assert manifest["distribution"] == "ad_hoc_local_test"
    assert manifest["project_root"] == str(PROJECT)
    build = PROJECT / "var/build/web"
    shipped = APP / "Contents/Resources/web"
    originals = sorted(path.relative_to(build) for path in build.rglob("*") if path.is_file())
    bundled = sorted(path.relative_to(shipped) for path in shipped.rglob("*") if path.is_file())
    assert originals == bundled, "Bundle has missing or stale static assets"
    for relative in originals:
        assert (build / relative).read_bytes() == (shipped / relative).read_bytes(), "Final app UI differs from tested build"
    strings = "\n".join(path.read_text() for path in shipped.rglob("*.js"))
    for expected in ("网络拓扑", "期望启用", "实时连接中断", "系统设置", "/discovery", "/metrics/history", "/diagnostics"):
        assert expected in strings, "Final app is missing a required V2 UI capability"


def test_frozen_v2_api_auth_readonly_and_diagnostic_error_privacy(packaged_api):
    client, process, runtime, log = packaged_api
    assert client.get("/api/v1/discovery").status_code == 401
    assert client.get("/api/v1/activity").status_code == 401
    authenticate(client, runtime)
    snapshot = client.get("/api/v1/discovery")
    assert snapshot.status_code == 200
    assert snapshot.headers["cache-control"] == "no-store"
    discovery = snapshot.json()
    assert discovery["ownership"] == "OBSERVED_EXTERNAL" and discovery["health"] == "UNKNOWN"
    assert not client.get("/api/v1/servers").json(), "Discovery itself must not create or adopt profiles"
    assert isinstance(client.get("/api/v1/activity").json(), list)
    response = client.post("/api/v1/servers", json={"name": "frozen synthetic", "host": "fixture.test", "user": "fixture", "mode": "DISABLED"})
    assert response.status_code == 201
    server = response.json()
    for window in ("5m", "1h", "24h", "7d"):
        history = client.get(f"/api/v1/servers/{server['id']}/metrics/history?range={window}")
        assert history.status_code == 200
        assert history.json()["summary"]["success_ratio"] is None
        assert history.json()["samples"] == []
    assert client.get(f"/api/v1/servers/{server['id']}/metrics/history?range=all").status_code == 422
    sentinel = "SYNTHETIC-KEY-ONLY"
    for url in (f"https://hubway.cc:{sentinel}/v1", f"https://[{sentinel}]/v1", f"https://hubway.cc\uff1a{sentinel}/v1"):
        rejected = client.post(f"/api/v1/servers/{server['id']}/diagnostics", json={"target_url": url})
        assert rejected.status_code == 422
        assert sentinel not in rejected.text
    for field, value in (("identity_file_ref", f"/fixture/../{sentinel}"), ("health_url", f"https://fixture.test/?api_key={sentinel}")):
        rejected = client.patch(f"/api/v1/servers/{server['id']}", json={field: value}, headers={"If-Match": str(server["revision"])})
        assert rejected.status_code == 422 and rejected.json()["code"] == "VALIDATION_ERROR"
        assert sentinel not in rejected.text
    accepted_target = client.post(f"/api/v1/servers/{server['id']}/diagnostics", json={})
    assert accepted_target.status_code == 409 and accepted_target.json()["code"] == "CONNECTION_REQUIRED"
    assert client.post(f"/api/v1/servers/{server['id']}/tests", json={"kind": "proxy"}).status_code == 409
    assert client.get(f"/api/v1/servers/{server['id']}").json()["desired_state"] == "STOPPED"
    assert sentinel not in log.read_text()
    assert process.poll() is None


def test_frozen_v2_external_controls_cannot_be_enabled_or_migrated(packaged_api):
    client, _, runtime, _ = packaged_api
    authenticate(client, runtime)
    response = client.post("/api/v1/servers", json={"name": "frozen external", "host": "fixture.test", "user": "fixture", "management": "OBSERVED_EXTERNAL"})
    assert response.status_code == 201
    server = response.json()
    for suffix, body in (("/tests", {"kind": "connection"}), ("/diagnostics", {}), ("/probes", {})):
        assert client.post(f"/api/v1/servers/{server['id']}" + suffix, json=body).status_code == 403
    for command in ("start", "stop", "restart"):
        assert client.post(f"/api/v1/servers/{server['id']}/actions/{command}").status_code == 403
    assert client.put(f"/api/v1/servers/{server['id']}/mode", json={"mode": "CLASH_HTTP"}, headers={"If-Match": str(server["revision"])}).status_code == 403
    proposal = client.post("/api/v1/migrations/proposals", json={"server_id": server["id"]}).json()
    assert proposal["execution_enabled"] is False and len(proposal["plan_sha256"]) == 64
    assert client.post(f"/api/v1/migrations/{proposal['proposal_id']}/execute").status_code == 403
    assert client.get(f"/api/v1/servers/{server['id']}").json()["management"] == "OBSERVED_EXTERNAL"
