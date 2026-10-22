import asyncio
import json
import socket

import pytest
from app.bootstrap import peer_uid, private_directory
from app.events import EventHub


def test_private_directory_rejects_symlink_parent(tmp_path):
    actual = tmp_path / "real"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        private_directory(alias / "runtime")
    assert not (actual / "runtime").exists()


def test_private_directory_is_restricted(tmp_path):
    directory = private_directory(tmp_path / "run")
    assert directory.stat().st_mode & 0o777 == 0o700


def test_unix_socket_peer_is_current_user():
    import os

    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        assert peer_uid(left) == os.getuid()
    finally:
        left.close()
        right.close()


@pytest.mark.asyncio
async def test_event_backpressure_requires_resync():
    hub = EventHub(None)
    queue = hub.subscribe()
    for number in range(129):
        await hub.publish({"type": "server.metric", "payload": {"number": number}})
    event = queue.get_nowait()
    assert event["type"] == "resync_required"
    assert event["revision"] == 129
    assert queue.qsize() == 0
    hub.unsubscribe(queue)
    assert not hub.listeners


@pytest.mark.asyncio
async def test_event_timestamp_and_revision_are_real():
    hub = EventHub(None)
    queue = hub.subscribe()
    await hub.publish({"type": "dependency.changed", "payload": {"state": "UNAVAILABLE"}})
    event = await asyncio.wait_for(queue.get(), 1)
    assert event["revision"] == 1
    assert event["event_id"]
    assert event["occurred_at"]
    assert json.loads(json.dumps(event))["payload"]["state"] == "UNAVAILABLE"
