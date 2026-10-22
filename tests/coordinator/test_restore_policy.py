import pytest
from app.db.repository import Repository
from app.tunnels.manager import TunnelManager


@pytest.mark.asyncio
async def test_crash_recovery_and_login_have_distinct_restore_policies(tmp_path):
    repo = Repository(tmp_path)
    values = [
        {"name": "crash-only", "auto_reconnect": True, "restore_on_login": False},
        {"name": "login", "auto_reconnect": False, "restore_on_login": True},
        {"name": "manual", "auto_reconnect": False, "restore_on_login": False},
    ]
    servers = [repo.create_server({"host": "127.0.0.1", "user": "test", **value}) for value in values]
    for server in servers:
        repo.update_server(server["id"], {"desired_state": "RUNNING"})
    stopped = repo.create_server({"name": "stopped", "host": "127.0.0.1", "user": "test",
                                  "auto_reconnect": True, "restore_on_login": True})
    manager = TunnelManager(tmp_path, repo)
    selected = []

    async def record_start(server_id):
        selected.append(server_id)
        return {}

    manager.start = record_start
    try:
        await manager.restore()
        assert selected == [servers[1]["id"]]
        selected.clear()
        await manager.restore(recover=True)
        assert set(selected) == {servers[0]["id"], servers[1]["id"]}
        assert stopped["id"] not in selected
    finally:
        await manager.close()
        repo.close()


@pytest.mark.asyncio
async def test_recovery_port_conflicts_are_bounded_and_manual_stop_is_preserved(tmp_path, monkeypatch):
    repo = Repository(tmp_path)
    server = repo.create_server({"name": "conflict", "host": "127.0.0.1", "user": "test"})
    repo.update_server(server["id"], {"desired_state": "RUNNING"})
    manager = TunnelManager(tmp_path, repo)
    calls = []
    delays = []

    async def conflict(_server_id):
        calls.append(_server_id)
        return {"state": "PORT_CONFLICT"}

    async def clock(delay):
        delays.append(delay)

    monkeypatch.setattr(manager, "start", conflict)
    monkeypatch.setattr(manager, "_start_locked", conflict)
    monkeypatch.setattr("app.tunnels.manager.asyncio.sleep", clock)
    try:
        result = await manager.restore(recover=True)
        assert result == [{"state": "PORT_CONFLICT"}]
        assert len(calls) == 4 and delays == [1, 2, 4]
        assert manager._runs == {}

        async def stopped_during_delay(delay):
            repo.update_server(server["id"], {"desired_state": "STOPPED"})

        calls.clear()
        monkeypatch.setattr("app.tunnels.manager.asyncio.sleep", stopped_during_delay)
        result = await manager.restore(recover=True)
        assert result[0]["state"] == "STOPPED"
        assert len(calls) == 1
        assert repo.get_server(server["id"])["desired_state"] == "STOPPED"
    finally:
        await manager.close()
        repo.close()
