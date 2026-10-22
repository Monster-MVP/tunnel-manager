import json
import os
import sqlite3
from uuid import uuid4

import pytest
from app.db.repository import Repository, RepositoryError
from app.schemas.inputs import ServerInput


def server(repo, **values):
    return repo.create_server({"name": "Test server", "host": "ssh.example.test", "user": "tester", **values})


def test_durable_desired_state_revision_and_online_backup(repo):
    value = server(repo)
    updated = repo.update_server(value["id"], {"desired_state": "RUNNING"}, expected_revision=1)
    assert updated["revision"] == 2
    with pytest.raises(RepositoryError, match="changed"):
        repo.update_server(value["id"], {"name": "stale"}, expected_revision=1)
    backup = repo.backup()
    with sqlite3.connect(backup) as connection:
        assert connection.execute("SELECT desired_state FROM servers").fetchone()[0] == "RUNNING"
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert os.stat(backup).st_mode & 0o777 == 0o600


def test_runtime_reopened_is_stale_and_tombstone_keeps_history(repo):
    value = server(repo)
    repo.save_runtime({"server_id": value["id"], "state": "HEALTHY", "stale": False})
    repo.add_sample(value["id"], {"state": "HEALTHY", "http_status": 200, "total_ms": 21})
    second = Repository(repo.data_dir)
    try:
        assert second.get_runtime(value["id"])["stale"] is True
    finally:
        second.close()
    repo.delete_server(value["id"])
    assert repo.get_server(value["id"]) is None
    assert len(repo.samples(value["id"])) == 1


def test_delete_running_resource_rejected_and_external_never_running(repo):
    owned = server(repo)
    repo.update_server(owned["id"], {"desired_state": "RUNNING"})
    with pytest.raises(RepositoryError) as caught:
        repo.delete_server(owned["id"])
    assert caught.value.code == "ACTIVE_RESOURCE"
    external = server(repo, management="OBSERVED_EXTERNAL")
    with pytest.raises(RepositoryError) as caught:
        repo.update_server(external["id"], {"desired_state": "RUNNING"})
    assert caught.value.code == "INVALID_DESIRED_STATE"


def test_config_import_atomic_and_group_ids_remapped(repo):
    group_id = str(uuid4())
    config = {"groups": [{"id": group_id, "name": "Workstations"}],
              "servers": [ServerInput(name="Import", host="example.test", user="u", group_id=group_id).model_dump()]}
    created = repo.import_configuration(config)
    assert created[0]["group_id"] == repo.list_groups()[0]["id"]
    assert created[0]["group_id"] != group_id
    before = len(repo.list_servers())
    config["groups"][0]["name"] = "new"
    config["servers"][0]["group_id"] = str(uuid4())
    with pytest.raises(RepositoryError):
        repo.import_configuration(config)
    assert len(repo.list_servers()) == before
    assert [group["name"] for group in repo.list_groups()] == ["Workstations"]


def test_idempotency_and_redacted_storage(repo):
    value = server(repo)
    first, created = repo.create_operation(value["id"], "start", "scope", "one", {"action": "start"})
    duplicate, created_again = repo.create_operation(value["id"], "start", "scope", "one", {"action": "start"})
    assert created and not created_again and duplicate["id"] == first["id"]
    with pytest.raises(RepositoryError) as caught:
        repo.create_operation(value["id"], "stop", "scope", "one", {"action": "stop"})
    assert caught.value.code == "IDEMPOTENCY_CONFLICT"
    repo.append_log(value["id"], "WARN", "ssh.example.test tester token=private /Users/a/.ssh/id_ed25519 10.1.2.3")
    repo.audit("test", value["id"], "OK", {"host": "ssh.example.test", "ticket": "secret", "message": "tester"})
    saved = json.dumps(repo.logs(value["id"]) + repo.audit_events())
    assert "ssh.example.test" not in saved and "token=private" not in saved and "/Users/a" not in saved


def test_storage_symlink_rejected(data_dir):
    (data_dir / "unsafe").symlink_to(data_dir, target_is_directory=True)
    with pytest.raises(RepositoryError) as caught:
        Repository(data_dir / "unsafe")
    assert caught.value.code == "UNSAFE_STORAGE_PATH"


def test_db_migration_checksum_mismatch_fails_closed(repo):
    repo.connection.execute("UPDATE schema_migrations SET checksum='tampered' WHERE version=1")
    repo.connection.commit()
    with pytest.raises(RepositoryError) as caught:
        Repository(repo.data_dir)
    assert caught.value.code == "MIGRATION_MISMATCH"
