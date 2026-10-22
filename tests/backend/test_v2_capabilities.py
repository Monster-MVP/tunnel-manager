from datetime import UTC, datetime, timedelta

import pytest
from app.api.discovery import _parse_ssh
from app.schemas.inputs import DiagnosticsInput


def test_read_only_ssh_discovery_does_not_evaluate_match_and_reads_no_identity(tmp_path):
    config = tmp_path / "config"
    identity = tmp_path / "DO_NOT_READ.key"
    config.write_text(f"Host workstation\n HostName example.test\n User fixture\n Port 2222\n IdentityFile {identity}\n RemoteForward 127.0.0.1:18991 127.0.0.1:18988\nMatch exec touch forbidden\n HostName evil.test\n User evil\n", encoding="utf-8")
    values, warnings, state, digest = _parse_ssh(config)
    assert state == "observed" and len(digest) == 64
    assert values[0]["host"] == "example.test" and values[0]["identity_file_ref"] == str(identity)
    assert values[0]["remote_proxy_port"] == 18991
    assert any("Match" in warning for warning in warnings)
    assert not identity.exists() and not (tmp_path / "forbidden").exists()


def test_discovery_missing_unreadable_symlink_states_are_distinct(tmp_path):
    assert _parse_ssh(tmp_path / "missing")[2] == "absent"
    target = tmp_path / "target"
    target.write_text("Host x\n HostName x.test\n User x\n", encoding="utf-8")
    link = tmp_path / "config"
    link.symlink_to(target)
    assert _parse_ssh(link)[2] == "uninspected"


def test_window_statistics_exclude_old_observations_and_preserve_no_data(repo):
    server = repo.create_server({"name": "fixture", "host": "fixture.test", "user": "fixture"})
    old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    now = datetime.now(UTC).isoformat()
    repo.add_sample(server["id"], {"observed_at": old, "state": "HEALTHY", "total_ms": 50})
    repo.add_sample(server["id"], {"observed_at": now, "state": "HEALTHY", "total_ms": 100})
    repo.add_sample(server["id"], {"observed_at": now, "state": "DEGRADED", "total_ms": 300})
    history = repo.samples_in_range(server["id"], "1h")
    assert len(history["samples"]) == 1 and history["samples"][0]["state"] == "DEGRADED"
    assert history["sampling"]["summary_scope"] == "ALL_OBSERVATIONS"
    assert history["summary"]["sample_count"] == 2 and history["summary"]["success_ratio"] == 0.5
    assert history["summary"]["p50_total_ms"] == 200
    assert repo.samples_in_range(server["id"], "24h")["summary"]["sample_count"] == 3
    empty = repo.create_server({"name": "empty", "host": "empty.test", "user": "fixture"})
    assert repo.samples_in_range(empty["id"], "7d")["summary"]["success_ratio"] is None


@pytest.mark.parametrize("url", ["https://hubway.cc/v1?key=secret", "https://hubway.cc:8443/v1", "https://evil.test/v1", "https://hubway.cc/v1/completions", "http://hubway.cc/v1", "https://user:password@hubway.cc/v1"])
def test_diagnostics_target_strict_allowlist(url):
    with pytest.raises(ValueError):
        DiagnosticsInput(target_url=url)


def test_new_capabilities_keep_auth_and_external_control_protection(authed):
    server = authed.post("/api/v1/servers", json={"name": "external", "host": "fixture.test", "user": "fixture", "management": "OBSERVED_EXTERNAL"}).json()
    assert authed.post(f"/api/v1/servers/{server['id']}/tests", json={"kind": "proxy"}).status_code == 403
    assert authed.post(f"/api/v1/servers/{server['id']}/diagnostics", json={}).status_code == 403
    history = authed.get(f"/api/v1/servers/{server['id']}/metrics/history?range=5m")
    assert history.status_code == 200 and history.json()["summary"]["sample_count"] == 0
    assert authed.get(f"/api/v1/servers/{server['id']}/metrics/history?range=30d").status_code == 422
    assert isinstance(authed.get("/api/v1/activity").json(), list)


def test_preflight_protected_production_port_never_claims_can_start(authed):
    server = authed.post("/api/v1/servers", json={"name": "protected", "host": "fixture.test", "user": "fixture", "remote_proxy_port": 17890}).json()
    result = authed.post(f"/api/v1/servers/{server['id']}/preflight").json()
    assert result["can_start"] is False
    assert "PROTECTED_PRODUCTION_PORT" in result["blocking_reasons"]
    assert result["remote_listener"] == "UNKNOWN" and result["production_control_enabled"] is False


def test_activity_contains_durable_connection_state_transition(repo):
    server = repo.create_server({"name": "activity", "host": "fixture.test", "user": "fixture"})
    repo.save_runtime({"server_id": server["id"], "state": "RECONNECTING", "reason_code": "SSH_DISCONNECTED", "generation": 3})
    repo.audit("start", server["id"], "SUCCEEDED", {})
    events = repo.activity_events()
    transition = next(item for item in events if item["action"] == "connection.state")
    assert transition["result"] == "RECONNECTING" and transition["details"]["reason_code"] == "SSH_DISCONNECTED"
    assert transition["id"].startswith("state-") and len(events) == 2
