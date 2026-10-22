import asyncio
import os
from pathlib import Path

import pytest
from app.db.repository import Repository
from app.proxies.manager import ProxyError, ProxyManager
from app.tunnels.manager import EngineError, TunnelManager


@pytest.fixture
def storage(tmp_path):
    # pytest --basetemp is always set to a project-local path by the runner.
    project = Path(__file__).resolve().parents[2]
    assert tmp_path.is_relative_to(project)
    repo = Repository(tmp_path / "data")
    yield repo
    repo.close()


def create_server(repo, **fields):
    return repo.create_server({"name": "isolated", "host": "127.0.0.1", "user": "testuser", **fields})


@pytest.mark.asyncio
async def test_external_resources_reject_every_control(storage):
    server = create_server(storage, management="OBSERVED_EXTERNAL")
    manager = TunnelManager(storage.data_dir, storage)
    try:
        for control in (manager.start, manager.stop, manager.restart, manager.probe):
            with pytest.raises(EngineError, match="observed only") as raised:
                await control(server["id"])
            assert raised.value.code == "EXTERNAL_RESOURCE"
        with pytest.raises(EngineError):
            await manager.set_mode(server["id"], "DISABLED")
        assert storage.get_server(server["id"])["desired_state"] == "STOPPED"
    finally:
        await manager.close()


@pytest.mark.asyncio
async def test_durable_start_failure_never_spawns(storage, monkeypatch):
    server = create_server(storage)
    manager = TunnelManager(storage.data_dir, storage)
    def failing_write(*_args, **_kwargs):
        raise OSError("unavailable")
    monkeypatch.setattr(storage, "update_server", failing_write)
    with pytest.raises(EngineError) as raised:
        await manager.start(server["id"])
    assert raised.value.code == "STORAGE_UNAVAILABLE"
    assert manager._runs == {}
    await manager.close()


@pytest.mark.asyncio
async def test_stop_cancels_pending_retry_and_is_persistent(storage):
    server = create_server(storage)
    manager = TunnelManager(storage.data_dir, storage)
    manager._desired[server["id"]] = "RUNNING"
    task = asyncio.create_task(asyncio.sleep(30))
    manager._monitors[server["id"]] = task
    result = await manager.stop(server["id"])
    await asyncio.gather(task, return_exceptions=True)
    assert result["state"] == "STOPPED"
    assert task.cancelled()
    assert storage.get_server(server["id"])["desired_state"] == "STOPPED"
    await manager.close()


@pytest.mark.asyncio
async def test_disabled_start_remains_stopped(storage):
    server = create_server(storage, mode="DISABLED")
    manager = TunnelManager(storage.data_dir, storage)
    result = await manager.start(server["id"])
    assert result["state"] == "STOPPED"
    assert storage.get_server(server["id"])["desired_state"] == "STOPPED"
    await manager.close()


def test_generated_profile_never_loads_user_config_or_executes_commands(storage):
    server = create_server(storage)
    manager = TunnelManager(storage.data_dir, storage)
    config, control = manager._profile(server, "test-alias", "a" * 32, 25000)
    content = config.read_text()
    assert "StrictHostKeyChecking yes" in content
    assert "PermitLocalCommand no" in content
    assert "Include " not in content
    assert "Match " not in content
    assert "ProxyCommand" not in content
    assert "RemoteForward 127.0.0.1:" in content
    assert len(os.fsencode(control)) <= 100
    assert config.stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_proxy_protected_ports_and_external_conflict(storage):
    proxy = ProxyManager(storage.data_dir)
    for port in (7890, 18888, 17890, 17891):
        with pytest.raises(ProxyError) as raised:
            await proxy.ensure_for_mode("MAC_DIRECT", port)
        assert raised.value.code == "PROTECTED_PORT"
    server = await asyncio.start_server(lambda reader, writer: writer.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        with pytest.raises(ProxyError) as raised:
            await proxy.ensure_for_mode("MAC_DIRECT", port)
        assert raised.value.code == "PORT_CONFLICT"
        assert await proxy.ensure_for_mode("CLASH_HTTP", port) == port
        await proxy.close()
        assert server.is_serving()
    finally:
        server.close()
        await server.wait_closed()
