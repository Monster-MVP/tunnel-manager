"""Independent attack cases. Only project-local synthetic credentials are used."""

from __future__ import annotations

import json
import os
import subprocess
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.monitoring.codex_model_test import (
    REMOTE_MODEL_SCRIPT,
    REMOTE_PREVIEW_SCRIPT,
    ModelPreview,
    ModelTestResult,
    build_remote_model_test_command,
    safe_model_api_result,
    validate_model,
    validate_model_base_url,
)
from app.db.repository import Repository
from app.tunnels.manager import EngineError, TunnelManager

ROOT = Path(__file__).resolve().parents[2]
SENTINEL = "SYNTHETIC-MODEL-SECURITY-CANARY-NOT-A-REAL-KEY"
BASE = "https://api.synthetic.example.com/v1"
SOURCE = "REMOTE_CODEX_AUTH_JSON"


@pytest.mark.parametrize("url", [
    "http://api.example.com/v1", "https://127.0.0.1/v1", "https://93.184.216.34/v1",
    "https://[::1]/v1", "https://localhost/v1", "https://localhost.local/v1",
    "https://metadata.google.internal/v1", "https://api.example.com:8443/v1",
    "https://user:password@api.example.com/v1", "https://api.example.com/v1?key=" + SENTINEL,
    "https://api.example.com/v1#" + SENTINEL, "https://api.example.com/v1/../secret",
    "https://api.example.com/v1/%2e%2e/secret", "https://api.example.com//secret",
    "https://api.example.com/v1\n", "https://api.example.com/v\t1", " https://api.example.com/v1",
    "https://api.example.com/v1\x00", "https://api.example.com/v1\\secret",
    "https://例子.com/v1", "https://api.example.com./v1", "https://-api.example.com/v1",
    "https://api.example.com/v1/$({})", "https://api.example.com/v1;touch-owned-marker",
])
def test_reviewed_url_rejects_nonpublic_or_ambiguous_sensitive_recipient(url):
    with pytest.raises(ValueError):
        validate_model_base_url(url)
    with pytest.raises(ValueError):
        build_remote_model_test_command(url, "synthetic-model", "responses", 19000)


def test_url_normalization_preserves_reviewed_authority_and_safe_base_path():
    assert validate_model_base_url("https://API.Example.COM:443/api/v1/") == "https://api.example.com/api/v1"
    assert validate_model_base_url(BASE) == BASE
    assert SENTINEL not in build_remote_model_test_command(BASE, "synthetic-model", "responses", 19000)


@pytest.mark.parametrize("model", ["", "m\nsecret", "m\tsecret", "m\x00secret", "m$(touch marker)",
    "m`touch marker`", "a" * 121, "中文", "m;touch marker", True, None])
def test_model_identifier_does_not_become_command_or_headers(model):
    with pytest.raises(ValueError):
        validate_model(model)


def preview(tmp_path, content):
    home = tmp_path / "synthetic-home"
    directory = home / ".codex"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    config = directory / "config.toml"
    config.write_text(content)
    config.chmod(0o600)
    # A FIFO would hang any attempted auth.json read. Preview must never open it.
    os.mkfifo(directory / "auth.json", mode=0o600)
    child = subprocess.run(["/usr/bin/python3", "-I", "-c", REMOTE_PREVIEW_SCRIPT],
        cwd=ROOT, env={"HOME": str(home), "PATH": "/usr/bin:/bin"}, capture_output=True, timeout=4)
    assert child.returncode == 0 and child.stderr == b""
    assert SENTINEL.encode() not in child.stdout and str(tmp_path).encode() not in child.stdout
    return ModelPreview.from_remote(child.stdout, 0).as_dict()


def test_preview_reads_only_safe_config_fields_not_auth_json(tmp_path):
    result = preview(tmp_path, f'model = "synthetic-model"\nmodel_provider = "synthetic"\n'
        f'[model_providers.synthetic]\nbase_url = "{BASE}"\nwire_api = "responses"\n'
        f'api_key = "{SENTINEL}"\nhttp_headers = {{Authorization = "Bearer {SENTINEL}"}}\n')
    assert result["config_state"] == "READY"
    assert result["base_url"] == BASE and result["model"] == "synthetic-model"
    assert SENTINEL not in json.dumps(result)


@pytest.mark.parametrize("content", [
    '"model_provider" = "synthetic"\n[model_providers.synthetic]\nbase_url = "https://api.example.com/v1"',
    "'model_provider' = 'synthetic'\n[model_providers.synthetic]\nbase_url = 'https://api.example.com/v1'",
    'model_provider = "synthetic"\n[model_providers."synthetic"]\nbase_url = "https://api.example.com/v1"',
    'model = "a"\nmodel = "b"',
    'model_provider = "synthetic"\nmodel_providers.synthetic.base_url = "https://api.example.com/v1"',
    'model_provider = "synthetic"\n[model_providers.synthetic]\n"base_url" = "https://api.example.com/v1"',
    'model_provider = "synthetic"\n[model_providers.synthetic]\nbase_url = "https://api.example.com/v1"\nbase_url = "https://evil.example.com"',
])
def test_preview_unsupported_or_duplicate_toml_never_silently_changes_origin(tmp_path, content):
    result = preview(tmp_path, content)
    assert result["config_state"] in {"INVALID_CONFIG", "UNSUPPORTED_PROVIDER"}
    assert result["base_url"] is None and result["model"] is None and result["wire_api"] is None


@pytest.mark.parametrize("value", [
    "https://user:" + SENTINEL + "@api.example.com/v1",
    "https://api.example.com/v1?api_key=" + SENTINEL,
    "https://api.example.com/v1#" + SENTINEL,
    "https://127.0.0.1/v1",
])
def test_preview_never_exports_credentials_from_url(tmp_path, value):
    result = preview(tmp_path, f'model_provider = "synthetic"\n[model_providers.synthetic]\nbase_url = "{value}"')
    assert result["config_state"] == "INVALID_CONFIG" and result["base_url"] is None


def protocol(**updates):
    return json.dumps({"version": 1, "state": "SUCCESS", "credential_state": "READABLE", "http_status": 200,
        "total_ms": 12.5, "reason_code": "SUCCESS", **updates}).encode()


@pytest.mark.parametrize("output", [
    b"{}", SENTINEL.encode(), b"[1]", b"\xff", protocol(secret=SENTINEL), protocol(state=SENTINEL),
    protocol(http_status=401), protocol(http_status=True), protocol(credential_state="OAUTH_ONLY"),
    protocol(total_ms=float("inf")), protocol(total_ms=-1), protocol(version=True),
    protocol(reason_code=SENTINEL), protocol(total_ms=None), protocol(reason_code="NETWORK_ERROR"),
    protocol() + b"\n" + SENTINEL.encode(),
])
def test_remote_protocol_fail_closed_without_raw_stdout(output):
    result = ModelTestResult.from_remote(output, 0).as_dict()
    assert result["state"] == "CHECK_UNAVAILABLE" and not result["llm_completion_verified"]
    assert SENTINEL not in json.dumps(result)


@pytest.mark.parametrize("exit_code", [1, 69, 127, 124, 255])
def test_failed_remote_exit_can_never_be_model_success(exit_code):
    result = ModelTestResult.from_remote(protocol(), exit_code).as_dict()
    assert result["state"] == "CHECK_UNAVAILABLE" and not result["llm_completion_verified"]


def test_public_api_result_reconstructs_fixed_fields_and_ignores_error_key_content():
    result = ModelTestResult.from_remote(protocol(), 0).as_dict()
    result.update(server_id=SENTINEL, ownership=SENTINEL, response_text=SENTINEL,
        ssh_connected=True, observed_at="2026-10-11T00:00:00Z")
    public = safe_model_api_result(result, "safe-server")
    assert public["state"] == "SUCCESS" and public["llm_completion_verified"]
    assert public["server_id"] == "safe-server" and public["ownership"] == "MANAGED"
    assert SENTINEL not in json.dumps(public)
    result["ssh_connected"] = False
    with pytest.raises(ValueError):
        safe_model_api_result(result, "safe-server")


def create_profile(client, management="MANAGED"):
    response = client.post("/api/v1/servers", json={"name": "independent model fixture", "host": "fixture.example.com",
        "user": "synthetic", "management": management})
    assert response.status_code == 201
    return response.json()


def payload(server, **updates):
    return {"source": SOURCE, "consent": True, "base_url": BASE, "model": "synthetic-model",
        "wire_api": "responses", "expected_revision": server["revision"], **updates}


def test_real_middleware_session_csrf_host_origin_and_consent_gate(secured_api):
    client, app = secured_api
    url = "/api/v1/servers/nonexistent/model-test"
    body = payload({"revision": 1})
    assert client.post(url, json=body).status_code == 401
    result = client.post("/api/v1/sessions/exchange", json={"ticket": app.state.security.issue_bootstrap_ticket()})
    client.headers.update({"Origin": app.state.security.origin, "X-CSRF-Token": result.json()["csrf"]})
    server = create_profile(client)
    url = f"/api/v1/servers/{server['id']}/model-test"
    assert client.post(url, json=payload(server), headers={"X-CSRF-Token": "wrong"}).status_code == 401
    assert client.post(url, json=payload(server), headers={"Origin": "https://evil.example.com"}).status_code == 403
    assert client.post(url, json=payload(server), headers={"Host": "evil.example.com"}).status_code == 403
    assert client.post(url, json=payload(server, consent=False)).status_code == 403
    assert not app.state.engine._runs


@pytest.mark.parametrize("updates", [
    {"consent": "true"}, {"consent": 1}, {"key": SENTINEL}, {"path": "/" + SENTINEL},
    {"command": "touch marker"}, {"expected_revision": True}, {"wire_api": "arbitrary"},
])
def test_model_request_rejects_key_path_command_and_ambiguous_fields(secured_session, updates):
    client, app = secured_session
    server = create_profile(client)
    response = client.post(f"/api/v1/servers/{server['id']}/model-test", json=payload(server, **updates))
    assert response.status_code == 422
    assert SENTINEL not in response.text
    assert not app.state.engine._runs


def test_stopped_and_external_profiles_never_auto_connect_or_use_credentials(secured_session, monkeypatch):
    client, app = secured_session
    async def forbidden(*args, **kwargs):
        raise AssertionError("Model-test may not start any child for STOPPED/external profiles")
    monkeypatch.setattr("asyncio.create_subprocess_exec", forbidden)
    server = create_profile(client)
    before = app.state.repo.get_server(server["id"])
    response = client.post(f"/api/v1/servers/{server['id']}/model-test", json=payload(server))
    assert response.status_code == 200 and response.json()["state"] == "CHECK_UNAVAILABLE"
    assert response.json()["model_completion"] == "NOT_TESTED"
    assert app.state.repo.get_server(server["id"]) == before
    external = create_profile(client, "OBSERVED_EXTERNAL")
    response = client.post(f"/api/v1/servers/{external['id']}/model-test", json=payload(external))
    assert response.status_code == 403 and response.json()["code"] == "EXTERNAL_RESOURCE"
    assert not app.state.engine._runs


def test_unexpected_model_exception_cannot_reflect_secret_or_provider_body(secured_session, monkeypatch):
    client, app = secured_session
    server = create_profile(client)
    async def malicious(*args, **kwargs):
        raise RuntimeError(SENTINEL)
    monkeypatch.setattr(app.state.engine, "codex_model_test", malicious)
    response = client.post(f"/api/v1/servers/{server['id']}/model-test", json=payload(server))
    assert response.status_code >= 400 and SENTINEL not in response.text
    assert SENTINEL not in json.dumps(client.get("/api/v1/activity").json())


@pytest.fixture
def independent_manager(tmp_path):
    repo = Repository(tmp_path / "data")
    server = repo.create_server({"name": "independent race fixture", "host": "fixture.example.com", "user": "synthetic"})
    engine = TunnelManager(tmp_path / "data", repo)
    handle = SimpleNamespace(generation=3, process=SimpleNamespace(returncode=None),
        config_path=tmp_path / "isolated.conf", control_socket=tmp_path / "isolated.sock", alias="synthetic")
    engine._runs[server["id"]] = handle
    engine._generation[server["id"]] = 3
    engine._assert_owned = AsyncMock()
    engine._control_check = AsyncMock(return_value=True)
    engine._execute = AsyncMock(return_value=(0, protocol(), SENTINEL.encode()))
    yield engine, server, handle
    repo.close()


async def invoke(engine, server):
    return await engine.codex_model_test(server["id"], SOURCE, True, BASE, "synthetic-model", "responses", server["revision"])


async def test_ownership_guard_and_no_fresh_ssh_fallback_precede_key_request(independent_manager):
    engine, server, _ = independent_manager
    engine._assert_owned.side_effect = EngineError("OWNERSHIP_MISMATCH", SENTINEL)
    with pytest.raises(EngineError) as error:
        await invoke(engine, server)
    assert error.value.code == "OWNERSHIP_MISMATCH"
    engine._execute.assert_not_awaited()
    engine._assert_owned.side_effect = None
    engine._control_check.return_value = False
    result = await invoke(engine, server)
    assert result["state"] == "CHECK_UNAVAILABLE" and not result["llm_completion_verified"]
    engine._execute.assert_not_awaited()


@pytest.mark.parametrize("change", ["generation", "handle", "revision", "exit"])
async def test_changed_authority_discards_model_success_and_stderr(independent_manager, change):
    engine, server, handle = independent_manager
    async def changed(*args):
        if change == "generation":
            engine._generation[server["id"]] += 1
        elif change == "handle":
            engine._runs.pop(server["id"])
        elif change == "revision":
            engine.repo.update_server(server["id"], {"name": "changed during request"})
        else:
            handle.process.returncode = 1
        return 0, protocol(), SENTINEL.encode()
    engine._execute.side_effect = changed
    result = await invoke(engine, server)
    assert result["state"] == "CHECK_UNAVAILABLE" and result["reason_code"] == "CONNECTION_CHANGED"
    assert not result["llm_completion_verified"] and SENTINEL not in json.dumps(result)
    assert not engine.repo.logs(server["id"])


async def test_revision_change_during_control_check_prevents_provider_call(independent_manager):
    engine, server, _ = independent_manager
    async def changed(*args):
        engine.repo.update_server(server["id"], {"name": "changed before request"})
        return True
    engine._control_check.side_effect = changed
    with pytest.raises(EngineError) as error:
        await invoke(engine, server)
    assert error.value.code == "REVISION_CONFLICT"
    engine._execute.assert_not_awaited()


async def test_probe_capacity_cancellation_never_calls_provider_or_holds_lock(independent_manager):
    engine, server, _ = independent_manager
    capacity = int(engine._settings()["max_concurrent_probes"])
    engine._active_probes = capacity
    waiting = asyncio.create_task(invoke(engine, server))
    await asyncio.sleep(0)
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    engine._execute.assert_not_awaited()
    assert engine._active_probes == capacity and not engine._lock(server["id"]).locked()
    engine._active_probes = 0
