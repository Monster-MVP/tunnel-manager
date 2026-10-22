import asyncio

from app.main import create_app
from fastapi.testclient import TestClient


def test_restoring_unreachable_profiles_does_not_block_console_startup(tmp_path):
    class WaitingEngine:
        cancelled = False
        closed = False

        async def restore(self):
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled = True

        async def close(self):
            self.closed = True

    engine = WaitingEngine()
    app = create_app(tmp_path, engine=engine)
    with TestClient(app, base_url="http://127.0.0.1:18401") as client:
        assert client.get("/healthz").json() == {"alive": True}
    assert engine.cancelled and engine.closed
