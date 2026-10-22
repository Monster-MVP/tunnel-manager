"""Recovery may retry a listener; it must never stop its existing owner."""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import asyncssh
import pytest
from app.db.repository import Repository
from app.tunnels.manager import TunnelManager

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.asyncio
async def test_recovery_persistent_remote_conflict_is_bounded_and_preserves_listener(tmp_path):
    assert tmp_path.is_relative_to(ROOT)
    connections = []

    class Peer(asyncssh.SSHServer):
        def connection_made(self, connection):
            connections.append(connection)

        def begin_auth(self, username):
            return False

        def server_requested(self, host, port):
            return host == "127.0.0.1" and port >= 1024

    async def owner_request(reader, writer):
        writer.close()
        await writer.wait_closed()

    key = asyncssh.generate_private_key("ssh-ed25519")
    ssh = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[key], server_factory=Peer)
    owner = await asyncio.start_server(owner_request, "127.0.0.1", 0)
    proxy = await asyncio.start_server(owner_request, "127.0.0.1", 0)
    repo = Repository(tmp_path / "data")
    known = repo.data_dir / "known_hosts"
    known.write_bytes(f"[127.0.0.1]:{ssh.get_port()} ".encode() + key.export_public_key())
    known.chmod(0o600)
    server = repo.create_server({"name": "QA collision recovery", "host": "127.0.0.1", "user": "qa",
        "ssh_port": ssh.get_port(), "mode": "CLASH_HTTP", "auto_reconnect": True, "restore_on_login": False,
        "proxy_port": proxy.sockets[0].getsockname()[1], "remote_proxy_port": owner.sockets[0].getsockname()[1]})
    repo.update_server(server["id"], {"desired_state": "RUNNING"})
    manager = TunnelManager(repo.data_dir, repo)
    try:
        started = asyncio.get_running_loop().time()
        result = await manager.restore(recover=True)
        assert asyncio.get_running_loop().time() - started < 11
        assert len(result) == 1 and result[0]["state"] == "PORT_CONFLICT", result
        assert not manager._runs
        assert owner.is_serving() and proxy.is_serving()
        assert repo.get_server(server["id"])["desired_state"] == "RUNNING"
        # A fresh connection proves this fixture owner remains reachable.
        with socket.socket() as client:
            client.settimeout(.5)
            assert client.connect_ex(("127.0.0.1", owner.sockets[0].getsockname()[1])) == 0
    finally:
        await manager.close()
        ssh.close()
        for connection in connections:
            connection.abort()
            await asyncio.wait_for(connection.wait_closed(), 2)
        await asyncio.wait_for(ssh.wait_closed(), 5)
        owner.close()
        proxy.close()
        await asyncio.wait_for(owner.wait_closed(), 5)
        await asyncio.wait_for(proxy.wait_closed(), 5)
        repo.close()
