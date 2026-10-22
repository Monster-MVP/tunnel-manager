from datetime import UTC, datetime

from app.db.repository import Repository


def test_retention_preserves_current_runtime_and_pending_operations(tmp_path):
    repo = Repository(tmp_path)
    server = repo.create_server({"name": "retention", "host": "localhost", "user": "test"})
    old = "2026-01-01T00:00:00Z"
    recent = "2026-10-09T00:00:00Z"
    repo.update_settings({"raw_retention_days": 1, "audit_retention_days": 7})
    repo.add_sample(server["id"], {"observed_at": old, "http_status": 200, "total_ms": 2})
    repo.add_sample(server["id"], {"observed_at": recent, "http_status": 503, "total_ms": 3})
    repo.save_runtime({"server_id": server["id"], "state": "FAILED", "observed_at": old})
    repo.audit("old", server["id"], "FAILED", {})
    repo.connection.execute("UPDATE audit_events SET occurred_at=?", (old,))
    repo.connection.commit()
    pending, _ = repo.create_operation(server["id"], "start", "test", None, {})
    terminal, _ = repo.create_operation(server["id"], "stop", "test", None, {})
    repo.update_operation(terminal["id"], "SUCCEEDED")
    repo.connection.execute("UPDATE operations SET updated_at=?", (old,))
    repo.connection.commit()

    counts = repo.purge_history(datetime(2026, 10, 10, tzinfo=UTC))
    assert counts["health_samples"] == 1
    assert counts["state_events"] == 1
    assert counts["audit_events"] == 1
    assert counts["operations"] == 1
    assert repo.samples(server["id"])[0]["http_status"] == 503
    assert repo.get_runtime(server["id"])["state"] == "FAILED"
    assert repo.get_operation(pending["id"])["status"] == "QUEUED"
    assert repo.get_operation(terminal["id"]) is None
    assert repo.get_server(server["id"]) is not None
    assert not any(repo.purge_history(datetime(2026, 10, 10, tzinfo=UTC)).values())
    repo.close()
