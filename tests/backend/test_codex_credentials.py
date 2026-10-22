"""Synthetic credential files only; no developer or production key is read."""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.api.routes import create_router
from app.api.security import SecurityManager, SecurityMiddleware
from app.monitoring.codex_credentials import (
    REMOTE_READABILITY_SCRIPT,
    SOURCE,
    CodexCredentialCheck,
    build_remote_codex_command,
)
from app.schemas.inputs import CodexCredentialCheckInput
from app.tunnels.manager import EngineError, TunnelManager
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

CANARY = "SYNTHETIC-KEY-NEVER-LEAVE-REMOTE-493821"


def write_auth(directory: Path, body: str | dict, mode: int = 0o600) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "auth.json"
    path.write_text(json.dumps(body) if isinstance(body, dict) else body, encoding="utf-8")
    path.chmod(mode)
    return path


def run_helper(home: Path, **environment) -> tuple[dict, bytes, bytes]:
    # Explicit isolated HOME and env. Do not inherit the developer's Codex home.
    process = subprocess.run([sys.executable, "-I", "-c", REMOTE_READABILITY_SCRIPT],
                             env={"HOME": str(home), **environment}, capture_output=True, timeout=5, check=False)
    assert process.returncode == 0
    assert CANARY.encode() not in process.stdout + process.stderr
    assert process.stderr == b""
    payload = json.loads(process.stdout)
    assert set(payload) == {"version", "state", "auth_mode", "source_location", "key_readable"}
    assert len(process.stdout) < 512
    return payload, process.stdout, process.stderr


def test_remote_helper_reads_synthetic_key_without_returning_material(tmp_path):
    write_auth(tmp_path / ".codex", {"OPENAI_API_KEY": CANARY})
    value, out, _ = run_helper(tmp_path)
    assert value == {"version": 1, "state": "READABLE", "auth_mode": "API_KEY",
                     "source_location": "HOME_DEFAULT", "key_readable": True}
    result = CodexCredentialCheck.from_remote(out, 0).as_dict()
    assert result["credential_state"] == "READABLE" and result["key_readable"] is True
    assert result["authentication"] == result["model_completion"] == "NOT_TESTED"
    assert result["llm_completion_verified"] is False
    assert str(tmp_path) not in json.dumps(result)
    assert not any(name in result for name in ("key", "key_mask", "key_length", "fingerprint", "path"))


def test_remote_codex_home_precedence_and_relative_path_is_not_silently_ignored(tmp_path):
    alternate = tmp_path / "alternate"
    write_auth(alternate, {"OPENAI_API_KEY": CANARY})
    write_auth(tmp_path / ".codex", {"auth_mode": "chatgpt", "tokens": {"access_token": CANARY}})
    assert run_helper(tmp_path, CODEX_HOME=str(alternate))[0]["source_location"] == "CODEX_HOME"
    fallback = run_helper(tmp_path, CODEX_HOME="relative-untrusted")[0]
    assert fallback["state"] == "UNREADABLE" and fallback["source_location"] == "CODEX_HOME"


@pytest.mark.parametrize(("body", "state", "mode", "readable"), [
    ({"auth_mode": "chatgpt", "tokens": {"access_token": CANARY, "id_token": CANARY}}, "OAUTH_ONLY", "OAUTH", False),
    ({"tokens": {}}, "OAUTH_ONLY", "OAUTH", False),
    ({"OPENAI_API_KEY": None, "auth_mode": "chatgpt"}, "OAUTH_ONLY", "OAUTH", False),
    ({"auth_mode": "api_key"}, "MISSING_KEY", "API_KEY", False),
    ({}, "MISSING_KEY", "UNKNOWN", False),
    ({"OPENAI_API_KEY": ""}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": "  "}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": "bad\r\nheader"}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": "bad\x00header"}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": "non-ascii-密钥"}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": "x" * 4097}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": {"secret": CANARY}}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": True}, "INVALID_KEY", "API_KEY", False),
    ("[1,2,3]", "INVALID_JSON", "UNKNOWN", None),
    ('{"OPENAI_API_KEY":"' + CANARY + '","OPENAI_API_KEY":"another"}', "INVALID_JSON", "UNKNOWN", None),
    ('{"OPENAI_API_KEY":NaN}', "INVALID_JSON", "UNKNOWN", None),
    ("{invalid " + CANARY, "INVALID_JSON", "UNKNOWN", None),
])
def test_helper_distinguishes_data_states_without_leaking_secrets(tmp_path, body, state, mode, readable):
    write_auth(tmp_path / ".codex", body)
    value, output, _ = run_helper(tmp_path)
    assert (value["state"], value["auth_mode"], value["key_readable"]) == (state, mode, readable)
    assert CodexCredentialCheck.from_remote(output, 0).state == state


def test_helper_missing_invalid_utf8_and_size_are_distinct(tmp_path):
    assert run_helper(tmp_path)[0]["state"] == "NOT_FOUND"
    path = write_auth(tmp_path / ".codex", "x" * 65537)
    assert run_helper(tmp_path)[0]["state"] == "TOO_LARGE"
    path.write_bytes(b"\xff\xfe")
    assert run_helper(tmp_path)[0]["state"] == "INVALID_JSON"


@pytest.mark.parametrize("unsafe", ["file_symlink", "parent_symlink", "directory", "fifo", "public", "unreadable", "hardlink"])
def test_helper_refuses_unsafe_file_without_following_or_blocking(tmp_path, unsafe):
    directory = tmp_path / ".codex"
    directory.mkdir()
    path = directory / "auth.json"
    if unsafe == "file_symlink":
        target = write_auth(tmp_path / "elsewhere", {"OPENAI_API_KEY": CANARY})
        path.symlink_to(target)
    elif unsafe == "parent_symlink":
        directory.rmdir()
        target = tmp_path / "elsewhere"
        write_auth(target, {"OPENAI_API_KEY": CANARY})
        directory.symlink_to(target, target_is_directory=True)
    elif unsafe == "directory":
        path.mkdir()
    elif unsafe == "fifo":
        os.mkfifo(path, 0o600)
    else:
        write_auth(directory, {"OPENAI_API_KEY": CANARY}, 0o644 if unsafe == "public" else 0 if unsafe == "unreadable" else 0o600)
        if unsafe == "hardlink":
            os.link(path, directory / "linked")
    value, _, _ = run_helper(tmp_path)
    assert value["state"] == "UNREADABLE" and value["key_readable"] is None


def protocol(**changes) -> bytes:
    value = {"version": 1, "state": "READABLE", "auth_mode": "API_KEY",
             "source_location": "HOME_DEFAULT", "key_readable": True}
    return json.dumps(value | changes).encode("ascii")


@pytest.mark.parametrize("output", [
    CANARY.encode(), b"x" * 513, b"\xff", b"[]", b"{}",
    protocol(secret=CANARY), protocol(state=CANARY), protocol(auth_mode=CANARY),
    protocol(source_location=CANARY), protocol(key_readable=CANARY), protocol(key_readable=1),
    protocol(key_readable=False), protocol(auth_mode="OAUTH"), protocol(version=True),
    protocol(state="UNREADABLE", auth_mode="UNKNOWN", key_readable=True),
    protocol(state="CHECK_UNAVAILABLE", auth_mode="UNKNOWN", key_readable=None),
    b'{"version":1,"version":1,"state":"READABLE","auth_mode":"API_KEY","source_location":"HOME_DEFAULT","key_readable":true}',
])
def test_local_parser_rejects_untrusted_protocol_without_reflecting_output(output):
    result = CodexCredentialCheck.from_remote(output, 0).as_dict()
    assert result["credential_state"] == "CHECK_UNAVAILABLE"
    assert result["reason_code"] == "INVALID_REMOTE_RESULT"
    assert CANARY not in json.dumps(result)


@pytest.mark.parametrize(("exit_code", "state", "reason"), [
    (69, "REMOTE_TOOL_UNAVAILABLE", "REMOTE_PYTHON_UNAVAILABLE"),
    (127, "REMOTE_TOOL_UNAVAILABLE", "REMOTE_PYTHON_UNAVAILABLE"),
    (124, "CHECK_UNAVAILABLE", "CHECK_TIMEOUT"),
    (255, "CHECK_UNAVAILABLE", "REMOTE_CHECK_FAILED"),
])
def test_transport_and_missing_python_results_do_not_parse_output(exit_code, state, reason):
    value = CodexCredentialCheck.from_remote(CANARY.encode(), exit_code).as_dict()
    assert value["credential_state"] == state and value["reason_code"] == reason
    assert value["key_readable"] is None and value["check_completed"] is False
    assert CANARY not in json.dumps(value)


def test_fixed_remote_command_uses_isolated_absolute_interpreter_and_no_key():
    command = build_remote_codex_command()
    assert "/usr/bin/python3 -I -c " in command
    assert shlex.quote(REMOTE_READABILITY_SCRIPT) in command
    assert CANARY not in command
    assert "cat " not in command and "grep " not in command


@pytest.mark.parametrize("payload", [{}, {"source": SOURCE}, {"source": SOURCE, "consent": "true"},
                                      {"source": SOURCE, "consent": 1},
                                      {"source": "LOCAL_ENVIRONMENT", "consent": True},
                                      {"source": SOURCE, "consent": True, "path": "/elsewhere"},
                                      {"source": SOURCE, "consent": True, "key": CANARY}])
def test_credential_input_requires_explicit_source_and_strict_consent(payload):
    with pytest.raises(ValueError):
        CodexCredentialCheckInput(**payload)


@pytest.fixture
def manager(repo, data_dir):
    server = repo.create_server({"name": "isolated", "host": "fixture.test", "user": "fixture"})
    engine = TunnelManager(data_dir, repo)
    return engine, server


def attach_fixture_handle(engine: TunnelManager, server_id: str):
    handle = SimpleNamespace(generation=3, process=SimpleNamespace(returncode=None),
                             config_path=Path("/fixture-only/config"), control_socket=Path("/fixture-only/socket"),
                             alias="fixture-only")
    engine._runs[server_id] = handle
    engine._generation[server_id] = 3
    engine._assert_owned = AsyncMock()
    engine._control_check = AsyncMock(return_value=True)
    engine._execute = AsyncMock(return_value=(0, protocol(), b""))
    return handle


async def test_manager_consent_and_external_checks_precede_execution(manager):
    engine, server = manager
    engine._execute = AsyncMock()
    with pytest.raises(EngineError, match="Confirm"):
        await engine.codex_credential_check(server["id"], SOURCE, False)
    with pytest.raises(EngineError) as error:
        await engine.codex_credential_check(server["id"], "LOCAL_ENVIRONMENT", True)
    assert error.value.code == "INVALID_CREDENTIAL_SOURCE"
    external = engine.repo.create_server({"name": "external", "host": "fixture.test", "user": "fixture", "management": "OBSERVED_EXTERNAL"})
    with pytest.raises(EngineError) as error:
        await engine.codex_credential_check(external["id"], SOURCE, True)
    assert error.value.code == "EXTERNAL_RESOURCE"
    engine._execute.assert_not_awaited()


async def test_manager_does_not_connect_when_no_existing_owned_channel(manager):
    engine, server = manager
    engine._execute = AsyncMock()
    engine._start_locked = AsyncMock()
    result = await engine.codex_credential_check(server["id"], SOURCE, True)
    assert result["credential_state"] == "CHECK_UNAVAILABLE" and result["reason_code"] == "CONNECTION_REQUIRED"
    assert result["ssh_connected"] is False and result["key_readable"] is None
    engine._execute.assert_not_awaited()
    engine._start_locked.assert_not_awaited()


async def test_manager_requires_control_master_and_never_independent_login(manager):
    engine, server = manager
    handle = attach_fixture_handle(engine, server["id"])
    result = await engine.codex_credential_check(server["id"], SOURCE, True)
    assert result["credential_state"] == "READABLE" and result["ssh_connected"] is True
    argv, timeout = engine._execute.await_args.args
    assert timeout == 8 and argv[0] == "/usr/bin/ssh"
    assert argv[argv.index("-S") + 1] == str(handle.control_socket)
    assert "-n" in argv and "ControlMaster=no" in argv and "ClearAllForwardings=yes" in argv
    assert "ProxyCommand=/usr/bin/false" in argv and argv[-1] == build_remote_codex_command()
    assert CANARY not in str(argv)
    assert engine._assert_owned.await_count == 3
    engine._control_check.return_value = False
    engine._execute.reset_mock()
    result = await engine.codex_credential_check(server["id"], SOURCE, True)
    assert result["credential_state"] == "CHECK_UNAVAILABLE"
    engine._execute.assert_not_awaited()


async def test_manager_fails_closed_on_ownership_change(manager):
    engine, server = manager
    attach_fixture_handle(engine, server["id"])
    engine._assert_owned.side_effect = EngineError("OWNERSHIP_MISMATCH", "Fixture ownership mismatch")
    with pytest.raises(EngineError) as error:
        await engine.codex_credential_check(server["id"], SOURCE, True)
    assert error.value.code == "OWNERSHIP_MISMATCH"
    engine._execute.assert_not_awaited()


async def test_manager_discards_generation_change_and_does_not_log_remote_stderr(manager):
    engine, server = manager
    attach_fixture_handle(engine, server["id"])
    async def changed(argv, timeout):
        engine._generation[server["id"]] += 1
        return 0, protocol(), CANARY.encode()
    engine._execute.side_effect = changed
    result = await engine.codex_credential_check(server["id"], SOURCE, True)
    assert result["credential_state"] == "CHECK_UNAVAILABLE" and result["reason_code"] == "CONNECTION_CHANGED"
    assert CANARY not in json.dumps(result)
    assert not engine.repo.logs(server["id"])


async def test_manager_discards_generation_change_while_waiting_for_capacity(manager):
    engine, server = manager
    attach_fixture_handle(engine, server["id"])
    engine._active_probes = int(engine._settings()["max_concurrent_probes"])
    waiting = asyncio.create_task(engine.codex_credential_check(server["id"], SOURCE, True))
    await asyncio.sleep(0)
    async with engine._probe_condition:
        engine._generation[server["id"]] += 1
        engine._active_probes = 0
        engine._probe_condition.notify_all()
    result = await waiting
    assert result["credential_state"] == "CHECK_UNAVAILABLE" and result["reason_code"] == "CONNECTION_CHANGED"
    engine._execute.assert_not_awaited()
    engine._control_check.assert_not_awaited()
    assert engine._active_probes == 0


@pytest.mark.parametrize(("return_code", "expected", "reason"), [
    (124, "CHECK_UNAVAILABLE", "CHECK_TIMEOUT"),
    (69, "REMOTE_TOOL_UNAVAILABLE", "REMOTE_PYTHON_UNAVAILABLE"),
    (255, "CHECK_UNAVAILABLE", "REMOTE_CHECK_FAILED"),
])
async def test_manager_timeout_and_tools_results_preserve_not_tested_claims(manager, return_code, expected, reason):
    engine, server = manager
    attach_fixture_handle(engine, server["id"])
    engine._execute.return_value = return_code, CANARY.encode(), CANARY.encode()
    result = await engine.codex_credential_check(server["id"], SOURCE, True)
    assert result["credential_state"] == expected and result["reason_code"] == reason
    assert result["authentication"] == result["model_completion"] == "NOT_TESTED"
    assert CANARY not in json.dumps(result) and not engine.repo.logs(server["id"])


async def test_manager_obeys_probe_capacity_and_cancellation(manager):
    engine, server = manager
    attach_fixture_handle(engine, server["id"])
    engine._active_probes = int(engine._settings()["max_concurrent_probes"])
    waiting = asyncio.create_task(engine.codex_credential_check(server["id"], SOURCE, True))
    await asyncio.sleep(0)
    engine._execute.assert_not_awaited()
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    assert engine._active_probes == int(engine._settings()["max_concurrent_probes"])
    engine._active_probes = 0
    engine._execute.side_effect = asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await engine.codex_credential_check(server["id"], SOURCE, True)
    assert engine._active_probes == 0 and not engine._lock(server["id"]).locked()


@pytest.fixture
def credential_api(repo):
    engine = SimpleNamespace(codex_credential_check=AsyncMock(return_value={
        "server_id": "fixture", "ownership": "MANAGED", "ssh_connected": True,
        "observed_at": "2026-10-11T00:00:00Z", **CodexCredentialCheck.from_remote(protocol(), 0).as_dict()}))
    app = FastAPI()
    security = SecurityManager("http://127.0.0.1:18401")
    app.state.security = security
    app.add_middleware(SecurityMiddleware, security=security)
    app.include_router(create_router(repo, engine))

    @app.exception_handler(HTTPException)
    async def errors(request, error):
        return JSONResponse(error.detail, status_code=error.status_code)

    with TestClient(app, base_url=security.origin) as client:
        yield client, security, engine


def authorize(client, security):
    response = client.post("/api/v1/sessions/exchange", json={"ticket": security.issue_bootstrap_ticket()})
    client.headers.update({"X-CSRF-Token": response.json()["csrf"], "Origin": security.origin})


def test_credential_endpoint_preserves_session_csrf_origin_and_consent_protection(credential_api, repo):
    client, security, engine = credential_api
    server = repo.create_server({"name": "fixture", "host": "fixture.test", "user": "fixture"})
    url = f"/api/v1/servers/{server['id']}/credentials/codex/check"
    payload = {"source": SOURCE, "consent": True}
    assert client.post(url, json=payload).status_code == 401
    authorize(client, security)
    assert client.post(url, json=payload, headers={"X-CSRF-Token": "wrong"}).status_code == 401
    assert client.post(url, json=payload, headers={"Origin": "https://evil.test"}).status_code == 403
    assert client.post(url, json=payload, headers={"Host": "evil.test"}).status_code == 403
    assert client.post(url, json={"source": SOURCE, "consent": False}).status_code == 403
    engine.codex_credential_check.assert_not_awaited()
    response = client.post(url, json=payload)
    assert response.status_code == 200 and response.json()["credential_state"] == "READABLE"
    engine.codex_credential_check.assert_awaited_once_with(server["id"], SOURCE, True)
    audit = next(item for item in repo.activity_events() if item["action"] == "server.credentials.codex.check")
    assert audit["details"] == {"source": SOURCE, "credential_state": "READABLE"}


def test_credential_endpoint_external_profile_and_extra_secret_rejected(credential_api, repo):
    client, security, engine = credential_api
    authorize(client, security)
    server = repo.create_server({"name": "external", "host": "fixture.test", "user": "fixture", "management": "OBSERVED_EXTERNAL"})
    url = f"/api/v1/servers/{server['id']}/credentials/codex/check"
    assert client.post(url, json={"source": SOURCE, "consent": True}).status_code == 403
    assert client.post(url, json={"source": SOURCE, "consent": True, "key": CANARY}).status_code == 422
    engine.codex_credential_check.assert_not_awaited()


def test_credential_endpoint_strips_faulty_engine_extra_fields_before_api_and_audit(credential_api, repo):
    client, security, engine = credential_api
    authorize(client, security)
    server = repo.create_server({"name": "fixture", "host": "fixture.test", "user": "fixture"})
    engine.codex_credential_check.return_value.update({"secret": CANARY, "server_id": CANARY,
                                                       "source_label": CANARY, "authentication": CANARY})
    response = client.post(f"/api/v1/servers/{server['id']}/credentials/codex/check", json={"source": SOURCE, "consent": True})
    assert response.status_code == 200 and response.json()["server_id"] == server["id"]
    assert response.json()["authentication"] == "NOT_TESTED" and CANARY not in response.text
    assert CANARY not in json.dumps(repo.activity_events())


@pytest.mark.parametrize("changes", [{"credential_state": CANARY}, {"auth_mode": CANARY},
                                    {"source_location": CANARY}, {"key_readable": CANARY},
                                    {"observed_at": CANARY}, {"reason_code": CANARY}])
def test_credential_endpoint_rejects_faulty_engine_fields_without_reflecting_or_auditing(credential_api, repo, changes):
    client, security, engine = credential_api
    authorize(client, security)
    server = repo.create_server({"name": "fixture", "host": "fixture.test", "user": "fixture"})
    engine.codex_credential_check.return_value.update(changes)
    response = client.post(f"/api/v1/servers/{server['id']}/credentials/codex/check", json={"source": SOURCE, "consent": True})
    assert response.status_code == 503 and response.json()["code"] == "CHECK_UNAVAILABLE"
    assert CANARY not in response.text and CANARY not in json.dumps(repo.activity_events())


@pytest.mark.parametrize("code", [None, "OWNERSHIP_MISMATCH"])
def test_credential_endpoint_sanitizes_unexpected_or_known_dependency_error(credential_api, repo, code):
    client, security, engine = credential_api
    authorize(client, security)
    server = repo.create_server({"name": "fixture", "host": "fixture.test", "user": "fixture"})
    engine.codex_credential_check.side_effect = RuntimeError(CANARY) if code is None else EngineError(code, CANARY, details={"secret": CANARY})
    response = client.post(f"/api/v1/servers/{server['id']}/credentials/codex/check", json={"source": SOURCE, "consent": True})
    assert response.status_code == (503 if code is None else 409) and CANARY not in response.text
    assert CANARY not in json.dumps(repo.activity_events())


def test_existing_unauthenticated_diagnostics_behavior_is_unchanged(authed):
    server = authed.post("/api/v1/servers", json={"name": "fixture", "host": "fixture.test", "user": "fixture"}).json()
    response = authed.post(f"/api/v1/servers/{server['id']}/diagnostics", json={})
    assert response.status_code == 503 and response.json()["code"] == "DEPENDENCY_UNAVAILABLE"
