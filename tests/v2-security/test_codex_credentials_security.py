"""Independent credential-read boundary checks using project-local sentinels only."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from app.monitoring.codex_credentials import (
    MAX_AUTH_BYTES,
    REMOTE_READABILITY_SCRIPT,
    SOURCE,
    CodexCredentialCheck,
    build_remote_codex_command,
)
from app.tunnels.manager import EngineError

SENTINEL = "SYNTHETIC-CODEX-KEY-NEVER-A-REAL-CREDENTIAL"
BODY = {"source": SOURCE, "consent": True}


def write_auth(directory: Path, value, *, raw: bytes | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "auth.json"
    path.write_bytes(raw if raw is not None else json.dumps(value).encode())
    path.chmod(0o600)
    return path


def run_helper(tmp_path: Path, directory: Path | None = None, *, codex_home: str | None = None):
    root = Path(__file__).resolve().parents[2]
    assert tmp_path.is_relative_to(root)
    home = tmp_path / "isolated-home"
    home.mkdir(exist_ok=True, mode=0o700)
    environment = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    if directory is not None or codex_home is not None:
        environment["CODEX_HOME"] = codex_home if codex_home is not None else str(directory)
    process = subprocess.run(["/usr/bin/python3", "-I", "-c", REMOTE_READABILITY_SCRIPT],
                             env=environment, cwd=root, capture_output=True, timeout=4, check=False)
    assert process.returncode == 0
    assert process.stderr == b""
    assert SENTINEL.encode() not in process.stdout
    assert str(tmp_path).encode() not in process.stdout
    parsed = CodexCredentialCheck.from_remote(process.stdout, process.returncode)
    assert parsed.reason_code is None, process.stdout
    return parsed.as_dict()


@pytest.mark.parametrize("document,state,mode,readable", [
    ({"OPENAI_API_KEY": SENTINEL}, "READABLE", "API_KEY", True),
    ({"auth_mode": "apikey", "OPENAI_API_KEY": SENTINEL}, "READABLE", "API_KEY", True),
    ({"auth_mode": "chatgpt", "tokens": {"access_token": SENTINEL}}, "OAUTH_ONLY", "OAUTH", False),
    ({"auth_mode": "oauth"}, "OAUTH_ONLY", "OAUTH", False),
    ({"tokens": {}}, "OAUTH_ONLY", "OAUTH", False),
    ({"auth_mode": "api_key"}, "MISSING_KEY", "API_KEY", False),
    ({}, "MISSING_KEY", "UNKNOWN", False),
    ({"auth_mode": {"secret": SENTINEL}}, "MISSING_KEY", "UNKNOWN", False),
    ({"OPENAI_API_KEY": ""}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": 123}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": True}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": [SENTINEL]}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": {"secret": SENTINEL}}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": SENTINEL + "\n"}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": SENTINEL + "\x00"}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": SENTINEL + "\u202e"}, "INVALID_KEY", "API_KEY", False),
    ({"OPENAI_API_KEY": "x" * 4097}, "INVALID_KEY", "API_KEY", False),
])
def test_helper_distinguishes_modes_and_never_transports_key(tmp_path, document, state, mode, readable):
    directory = tmp_path / "codex"
    write_auth(directory, document)
    result = run_helper(tmp_path, directory)
    assert result["credential_state"] == state
    assert result["auth_mode"] == mode and result["key_readable"] is readable
    assert result["source_location"] == "CODEX_HOME" and result["check_completed"]
    assert result["authentication"] == result["model_completion"] == "NOT_TESTED"
    assert result["llm_completion_verified"] is False
    assert set(result) == {"source", "source_label", "credential_state", "auth_mode", "source_location",
                           "key_readable", "check_completed", "reason_code", "authentication",
                           "model_completion", "llm_completion_verified"}


@pytest.mark.parametrize("raw", [
    b"[1,2]", b"null", b"{", b"\xff", b'\xef\xbb\xbf{"OPENAI_API_KEY":"x"}',
    b'{"OPENAI_API_KEY":"first","OPENAI_API_KEY":"second"}',
    b'{"OPENAI_API_KEY":"x","extra":NaN}',
    b'[' * 2000 + b']' * 2000,
])
def test_helper_rejects_malformed_or_ambiguous_json(tmp_path, raw):
    directory = tmp_path / "codex"
    write_auth(directory, {}, raw=raw)
    result = run_helper(tmp_path, directory)
    assert result["credential_state"] == "INVALID_JSON" and result["key_readable"] is None


def test_helper_size_boundary_and_missing_file_are_honest(tmp_path):
    directory = tmp_path / "codex"
    content = json.dumps({"OPENAI_API_KEY": SENTINEL}).encode()
    file = write_auth(directory, {}, raw=content + b" " * (MAX_AUTH_BYTES - len(content)))
    assert run_helper(tmp_path, directory)["credential_state"] == "READABLE"
    file.write_bytes(content + b" " * (MAX_AUTH_BYTES + 1 - len(content)))
    assert run_helper(tmp_path, directory)["credential_state"] == "TOO_LARGE"
    file.unlink()
    missing = run_helper(tmp_path, directory)
    assert missing["credential_state"] == "NOT_FOUND" and missing["key_readable"] is False


@pytest.mark.parametrize("kind", ["file-symlink", "parent-symlink", "hardlink", "fifo", "directory", "world-readable", "no-read"])
def test_helper_rejects_unsafe_file_without_leak_or_blocking(tmp_path, kind):
    directory = tmp_path / "codex"
    original = write_auth(tmp_path / "original", {"OPENAI_API_KEY": SENTINEL})
    directory.mkdir(mode=0o700)
    auth = directory / "auth.json"
    if kind == "file-symlink":
        auth.symlink_to(original)
    elif kind == "parent-symlink":
        directory.rmdir()
        directory.symlink_to(original.parent, target_is_directory=True)
    elif kind == "hardlink":
        os.link(original, auth)
    elif kind == "fifo":
        os.mkfifo(auth, mode=0o600)
    elif kind == "directory":
        auth.mkdir(mode=0o700)
    else:
        auth = write_auth(directory, {"OPENAI_API_KEY": SENTINEL})
        auth.chmod(0o644 if kind == "world-readable" else 0o000)
    try:
        result = run_helper(tmp_path, directory)
        assert result["credential_state"] == "UNREADABLE" and result["key_readable"] is None
    finally:
        if kind == "no-read":
            auth.chmod(0o600)


def test_helper_home_default_relative_override_and_shell_metacharacters(tmp_path):
    home = tmp_path / "isolated-home"
    write_auth(home / ".codex", {"OPENAI_API_KEY": SENTINEL})
    default = run_helper(tmp_path)
    assert default["credential_state"] == "READABLE" and default["source_location"] == "HOME_DEFAULT"
    relative = run_helper(tmp_path, codex_home="relative-CODEX_HOME")
    assert relative["credential_state"] == "UNREADABLE" and relative["source_location"] == "CODEX_HOME"
    empty = run_helper(tmp_path, codex_home="")
    assert empty["credential_state"] == "UNREADABLE" and empty["source_location"] == "CODEX_HOME"
    marker = tmp_path / "should-not-exist"
    directory = tmp_path / ("$(touch should-not-exist);`touch should-not-exist`")
    write_auth(directory, {"OPENAI_API_KEY": SENTINEL})
    assert run_helper(tmp_path, directory)["credential_state"] == "READABLE"
    assert not marker.exists()
    traversal = run_helper(tmp_path, codex_home=str(directory / ".." / directory.name))
    assert traversal["credential_state"] == "UNREADABLE"
    assert "/usr/bin/python3 -I -c" in build_remote_codex_command()
    assert SENTINEL not in build_remote_codex_command()


def protocol(**updates):
    return json.dumps({"version": 1, "state": "READABLE", "auth_mode": "API_KEY",
                       "source_location": "CODEX_HOME", "key_readable": True, **updates}).encode()


@pytest.mark.parametrize("output", [
    SENTINEL.encode(), b"\xff", b"[1]", b"{}", b"{" + SENTINEL.encode(),
    protocol(secret=SENTINEL), protocol(state=SENTINEL), protocol(auth_mode=[SENTINEL]),
    protocol(source_location={"key": SENTINEL}), protocol(key_readable=1), protocol(version=True),
    protocol(state="READABLE", key_readable=False), protocol(state="READABLE", auth_mode="OAUTH"),
    protocol(state="OAUTH_ONLY", auth_mode="API_KEY", key_readable=False),
    protocol(state="NOT_FOUND", auth_mode="API_KEY", key_readable=False),
    b'\nBANNER-' + SENTINEL.encode() + b'\n' + protocol(), protocol() + SENTINEL.encode(),
    protocol() + b" " * 513, b'{' + b'"version":1,"version":1,"state":"READABLE",'
    b'"auth_mode":"API_KEY","source_location":"CODEX_HOME","key_readable":true}',
])
def test_remote_protocol_is_exact_and_never_reflects_attacker_output(output):
    result = CodexCredentialCheck.from_remote(output, 0).as_dict()
    assert result["credential_state"] == "CHECK_UNAVAILABLE"
    assert result["reason_code"] == "INVALID_REMOTE_RESULT" and not result["check_completed"]
    assert SENTINEL not in json.dumps(result)
    assert result["key_readable"] is None


@pytest.mark.parametrize("rc,state,reason", [
    (69, "REMOTE_TOOL_UNAVAILABLE", "REMOTE_PYTHON_UNAVAILABLE"),
    (127, "REMOTE_TOOL_UNAVAILABLE", "REMOTE_PYTHON_UNAVAILABLE"),
    (124, "CHECK_UNAVAILABLE", "CHECK_TIMEOUT"),
    (1, "CHECK_UNAVAILABLE", "REMOTE_CHECK_FAILED"),
])
def test_remote_exit_errors_discard_stdout_and_preserve_unavailability(rc, state, reason):
    result = CodexCredentialCheck.from_remote(SENTINEL.encode(), rc).as_dict()
    assert result["credential_state"] == state and result["reason_code"] == reason
    assert result["key_readable"] is None and not result["check_completed"]
    assert SENTINEL not in json.dumps(result)


def create_profile(client):
    response = client.post("/api/v1/servers", json={"name": "isolated credential security",
                                                  "host": "fixture.test", "user": "fixture", "mode": "DISABLED"})
    assert response.status_code == 201
    return response.json()


def endpoint(server):
    return f"/api/v1/servers/{server['id']}/credentials/codex/check"


def test_credential_check_requires_authenticated_session(secured_api):
    client, _ = secured_api
    response = client.post("/api/v1/servers/00000000-0000-0000-0000-000000000000/credentials/codex/check", json=BODY)
    # Security middleware rejects unauthenticated POST before the route; this
    # error contains no credential result and is distinct from result caching.
    assert response.status_code == 401
    assert SENTINEL not in response.text


def test_credential_check_requires_csrf_and_rejects_foreign_origins(secured_session, monkeypatch):
    client, app = secured_session
    server = create_profile(client)
    called = []
    async def forbidden(*args):
        called.append(args)
        raise AssertionError("Read must not occur before security checks")
    monkeypatch.setattr(app.state.engine, "codex_credential_check", forbidden)
    for headers in ({"X-CSRF-Token": ""}, {"Origin": "https://attacker.test"},
                    {"Host": "127.0.0.1:18401.attacker.test"}):
        result = client.post(endpoint(server), json=BODY, headers=headers)
        assert result.status_code in {401, 403}
    assert not called and not app.state.engine._runs


@pytest.mark.parametrize("body,status", [
    ({"source": SOURCE, "consent": False}, 403),
    ({"source": SOURCE}, 422),
    ({"source": SOURCE, "consent": "true"}, 422),
    ({"source": SOURCE, "consent": 1}, 422),
    ({"source": SENTINEL, "consent": True}, 422),
    ({"source": SOURCE, "consent": True, "path": "/" + SENTINEL}, 422),
    ({"source": SOURCE, "consent": True, "api_key": SENTINEL}, 422),
])
def test_invalid_source_or_consent_never_read_or_reflect_secret(secured_session, monkeypatch, body, status):
    client, app = secured_session
    server = create_profile(client)
    before = app.state.repo.get_server(server["id"])
    called = []
    async def forbidden(*args):
        called.append(args)
        raise AssertionError("Read must not occur for invalid consent/source")
    monkeypatch.setattr(app.state.engine, "codex_credential_check", forbidden)
    response = client.post(endpoint(server), json=body)
    assert response.status_code == status and SENTINEL not in response.text
    assert not called and app.state.repo.get_server(server["id"]) == before
    assert not app.state.engine._runs


def test_external_profile_never_checks_credentials(secured_session, monkeypatch):
    client, app = secured_session
    server = create_profile(client)
    app.state.repo.update_server(server["id"], {"management": "OBSERVED_EXTERNAL"})
    called = []
    async def forbidden(*args):
        called.append(args)
        raise AssertionError("External resources must not be read")
    monkeypatch.setattr(app.state.engine, "codex_credential_check", forbidden)
    response = client.post(endpoint(server), json=BODY)
    assert response.status_code == 403 and response.json()["code"] == "EXTERNAL_RESOURCE"
    assert not called and not app.state.engine._runs


def test_stopped_profile_returns_unknown_without_launch_or_state_mutation(secured_session, monkeypatch):
    client, app = secured_session
    server = create_profile(client)
    before = app.state.repo.get_server(server["id"])
    async def forbidden(*args, **kwargs):
        raise AssertionError("Credential check cannot start any child on STOPPED")
    monkeypatch.setattr("asyncio.create_subprocess_exec", forbidden)
    response = client.post(endpoint(server), json=BODY)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    result = response.json()
    assert result["credential_state"] == "CHECK_UNAVAILABLE" and result["reason_code"] == "CONNECTION_REQUIRED"
    assert result["key_readable"] is None and not result["ssh_connected"]
    assert app.state.repo.get_server(server["id"]) == before and not app.state.engine._runs
    assert not app.state.engine.proxy.snapshot()["managed_tinyproxy"]


def test_unexpected_credential_exception_never_reflects_secret(secured_session, monkeypatch):
    client, app = secured_session
    server = create_profile(client)
    async def malicious_error(*args):
        raise RuntimeError("remote auth.json parse failure: " + SENTINEL)
    monkeypatch.setattr(app.state.engine, "codex_credential_check", malicious_error)
    response = client.post(endpoint(server), json=BODY)
    assert response.status_code >= 400
    assert SENTINEL not in response.text, "Credential route reflected an arbitrary exception secret"
    assert SENTINEL not in json.dumps(client.get("/api/v1/activity").json())


def test_known_credential_error_never_reflects_sensitive_message_or_details(secured_session, monkeypatch):
    client, app = secured_session
    server = create_profile(client)
    async def malformed_known_error(*args):
        raise EngineError("OWNERSHIP_MISMATCH", SENTINEL, details={"remote_path": "/" + SENTINEL})
    monkeypatch.setattr(app.state.engine, "codex_credential_check", malformed_known_error)
    response = client.post(endpoint(server), json=BODY)
    assert response.status_code == 409 and response.json()["code"] == "OWNERSHIP_MISMATCH"
    assert SENTINEL not in response.text


@pytest.mark.parametrize("mutations", [
    {"secret": SENTINEL, "key_mask": SENTINEL, "key_length": 4096, "path": "/" + SENTINEL},
    {"credential_state": SENTINEL}, {"source_location": SENTINEL}, {"reason_code": SENTINEL},
    {"authentication": SENTINEL}, {"model_completion": SENTINEL},
    {"source_label": SENTINEL}, {"observed_at": SENTINEL}, {"server_id": SENTINEL},
])
def test_faulty_engine_result_cannot_transport_or_persist_sensitive_extra_fields(secured_session, monkeypatch, mutations):
    client, app = secured_session
    server = create_profile(client)
    document = {"server_id": server["id"], "ownership": "MANAGED", "ssh_connected": True,
                "observed_at": "2026-10-11T00:00:00Z", **CodexCredentialCheck.from_remote(protocol(), 0).as_dict(),
                **mutations}
    async def faulty_result(*args):
        return document
    monkeypatch.setattr(app.state.engine, "codex_credential_check", faulty_result)
    response = client.post(endpoint(server), json=BODY)
    assert response.status_code in {200, 503}
    assert SENTINEL not in response.text
    assert SENTINEL not in json.dumps(client.get("/api/v1/activity").json())
    for path in app.state.repo.data_dir.rglob("*"):
        if path.is_file():
            assert SENTINEL.encode() not in path.read_bytes(), path
