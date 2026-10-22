from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4


class EventHub:
    def __init__(self, repo):
        self.repo = repo
        self.revision = 0
        self.listeners: set[asyncio.Queue] = set()
        self.runtime_provider = None

    async def publish(self, event: dict) -> None:
        self.revision += 1
        envelope = {
            "event_id": str(uuid4()),
            "revision": self.revision,
            "occurred_at": datetime.now(UTC).isoformat(),
            **event,
        }
        for queue in tuple(self.listeners):
            if queue.full():
                while not queue.empty():
                    queue.get_nowait()
                queue.put_nowait({"type": "resync_required", "revision": self.revision})
            else:
                queue.put_nowait(envelope)

    def snapshot(self) -> dict:
        servers = self.repo.list_servers()
        return {
            "type": "snapshot",
            "revision": self.revision,
            "payload": {
                "servers": servers,
                "runtimes": {s["id"]: self.runtime_provider(s["id"]) if self.runtime_provider
                             else self.repo.get_runtime(s["id"]) for s in servers},
            },
        }

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=128)
        self.listeners.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self.listeners.discard(queue)
