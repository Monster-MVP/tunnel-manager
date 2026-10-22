import asyncio
import uuid
from collections import deque
from types import SimpleNamespace

import pytest
from app.proxies.manager import ProxyError, ProxyManager, ProxyProcess
from app.tunnels.manager import EngineError, RunHandle, TunnelManager, _digest


@pytest.mark.asyncio
async def test_changed_owned_ssh_profile_refuses_signal(security_repo):
    profile = security_repo.create_server({"name": "isolated", "host": "127.0.0.1", "user": "tester"})
    manager = TunnelManager(security_repo.data_dir, security_repo)
    process = await asyncio.create_subprocess_exec("/bin/sleep", "30")
    run_id = uuid.uuid4().hex
    config, control = manager._profile(profile, "isolated-test", run_id, 25001)
    argv = ("/bin/sleep", "30")
    handle = RunHandle(profile["id"], run_id, 1, "isolated-test-nonce", process, config, control,
                       "isolated-test", argv, _digest(config.read_bytes()))
    handle.signature = await manager._signature(process)
    manager._runs[profile["id"]] = handle
    manager._owned[run_id] = (process, process.pid, handle.nonce, argv, config, control)
    try:
        config.write_text(config.read_text() + "# externally changed\n")
        with pytest.raises(EngineError) as error:
            await manager._dispose(handle)
        assert error.value.code == "OWNERSHIP_MISMATCH"
        assert process.returncode is None
    finally:
        manager._runs.clear()
        manager._owned.clear()
        if process.returncode is None:
            process.terminate()
        await process.wait()
        await manager.close()


@pytest.mark.asyncio
async def test_proxy_reference_count_preserves_shared_child(security_repo):
    proxy = ProxyManager(security_repo.data_dir)
    process = await asyncio.create_subprocess_exec("/bin/sleep", "30")
    managed = ProxyProcess(process, 25002, security_repo.data_dir / "synthetic.conf", {"first", "second"})
    proxy._managed[managed.port] = managed
    try:
        await proxy.release("first")
        assert process.returncode is None and managed.users == {"second"}
        await proxy.release("second")
        assert process.returncode is not None and not proxy._managed
    finally:
        if process.returncode is None:
            process.terminate()
        await process.wait()


@pytest.mark.asyncio
async def test_proxy_replaced_ownership_refuses_signal(security_repo):
    proxy = ProxyManager(security_repo.data_dir)
    process = await asyncio.create_subprocess_exec("/bin/sleep", "30")
    old = ProxyProcess(process, 25003, security_repo.data_dir / "first.conf")
    replacement = ProxyProcess(process, 25003, security_repo.data_dir / "second.conf")
    proxy._managed[old.port] = replacement
    try:
        with pytest.raises(ProxyError) as error:
            await proxy._stop(old)
        assert error.value.code == "OWNERSHIP_MISMATCH"
        assert process.returncode is None
    finally:
        proxy._managed.clear()
        if process.returncode is None:
            process.terminate()
        await process.wait()


@pytest.mark.asyncio
async def test_live_log_chunks_never_leak_sensitive_host(security_repo):
    sensitive_host = "secret-host-fragment.example.test"
    profile = security_repo.create_server({"name": "isolated", "host": sensitive_host, "user": "tester"})
    events = []
    manager = TunnelManager(security_repo.data_dir, security_repo, publish=events.append)
    stream = asyncio.StreamReader()
    handle = SimpleNamespace(server_id=profile["id"], stderr=deque(maxlen=40))
    drain = asyncio.create_task(manager._drain(handle, stream))
    try:
        for chunk in (b"remote banner: secret-host-", b"fragment.example.test\n"):
            stream.feed_data(chunk)
            await asyncio.sleep(0.01)
        stream.feed_eof()
        await drain
        all_messages = "".join(event["payload"]["message"] for event in events)
        assert sensitive_host not in all_messages
        persisted = "".join(log["message"] for log in security_repo.logs(profile["id"]))
        assert sensitive_host not in persisted
    finally:
        if not drain.done():
            drain.cancel()
            await asyncio.gather(drain, return_exceptions=True)
        await manager.close()


@pytest.mark.asyncio
async def test_live_log_private_key_marker_is_redacted(security_repo):
    profile = security_repo.create_server({"name": "isolated", "host": "example.test", "user": "tester"})
    events = []
    manager = TunnelManager(security_repo.data_dir, security_repo, publish=events.append)
    stream = asyncio.StreamReader()
    handle = SimpleNamespace(server_id=profile["id"], stderr=deque(maxlen=40))
    synthetic = "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-SECRET-NOT-A-KEY\n"
    try:
        stream.feed_data(synthetic.encode())
        stream.feed_eof()
        await manager._drain(handle, stream)
        serialized = str(events)
        assert "SYNTHETIC-SECRET-NOT-A-KEY" not in serialized
    finally:
        await manager.close()
