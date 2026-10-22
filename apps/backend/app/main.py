from __future__ import annotations

import asyncio
import contextlib
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException
from starlette.staticfiles import StaticFiles

from app.api.routes import create_router
from app.api.security import SecurityManager, SecurityMiddleware
from app.db.repository import Repository, RepositoryError
from app.events import EventHub
from app.tunnels.manager import TunnelManager


def create_app(
    data_dir: Path,
    web_dir: Path | None = None,
    engine=None,
    bootstrap_ticket: str | None = None,
    origin: str = "http://127.0.0.1:18401",
    tinyproxy_executable: str | None = None,
    recover_desired: bool = False,
) -> FastAPI:
    repo = Repository(Path(data_dir))
    hub = EventHub(repo)
    manager = engine or TunnelManager(
        Path(data_dir), repo, publish=hub.publish, tinyproxy_executable=tinyproxy_executable
    )
    hub.runtime_provider = getattr(manager, "snapshot", None)
    security = SecurityManager(origin, bootstrap_ticket=bootstrap_ticket)

    @asynccontextmanager
    async def lifespan(application):
        await asyncio.to_thread(repo.purge_history)
        async def restore_connections():
            try:
                if recover_desired:
                    await manager.restore(recover=True)
                else:
                    await manager.restore()
            except Exception:  # noqa: BLE001 - restoration failure must not strand the control console.
                await hub.publish({"type": "restore.error", "payload": {"code": "RESTORE_FAILED"}})

        restoring = asyncio.create_task(restore_connections())

        async def maintain_history():
            while True:
                await asyncio.sleep(3600)
                try:
                    await asyncio.to_thread(repo.purge_history)
                except RepositoryError as error:
                    await hub.publish({"type": "storage.error", "payload": {"code": error.code}})

        maintenance = asyncio.create_task(maintain_history())
        try:
            yield
        finally:
            maintenance.cancel()
            restoring.cancel()
            await asyncio.gather(maintenance, restoring, return_exceptions=True)
            tasks = tuple(getattr(router, "control_tasks", ()))
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            await manager.close()
            if hasattr(repo, "close"):
                repo.close()

    app = FastAPI(
        title="Tunnel Manager",
        version="2.0.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.repo = repo
    app.state.engine = manager
    app.state.events = hub
    app.state.security = security
    app.add_middleware(SecurityMiddleware, security=security)
    router = create_router(repo, manager, hub)
    app.include_router(router)

    @app.exception_handler(RepositoryError)
    async def repository_error(request, error):
        return JSONResponse(
            {
                "code": error.code,
                "message": error.message,
                "details": error.details,
                "correlation_id": str(uuid4()),
            },
            status_code=error.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        fields = [
            {"field": ".".join(map(str, item["loc"])), "message": item["msg"]} for item in error.errors()
        ]
        return JSONResponse(
            {
                "code": "VALIDATION_ERROR",
                "message": "Invalid request fields",
                "details": {"fields": fields},
                "correlation_id": str(uuid4()),
            },
            status_code=422,
        )

    @app.exception_handler(HTTPException)
    async def http_error(request, error):
        detail = (
            error.detail
            if isinstance(error.detail, dict)
            else {"code": "REQUEST_REJECTED", "message": str(error.detail)}
        )
        return JSONResponse({**detail, "correlation_id": str(uuid4())}, status_code=error.status_code)

    @app.get("/healthz")
    async def alive():
        return {"alive": True}

    @app.websocket("/api/v1/ws")
    async def websocket(ws: WebSocket):
        session = await security.authenticate_websocket(ws)
        if session is None:
            with contextlib.suppress(RuntimeError):
                await ws.close(code=1008)
            return
        queue = hub.subscribe()
        await ws.send_json(hub.snapshot())

        async def receive():
            while True:
                message = await ws.receive_json()
                if not security.current(session.token) or not isinstance(message, dict):
                    await ws.close(code=1008)
                    raise WebSocketDisconnect(code=1008)
                if not isinstance(message.get("type"), str) or message.get("type") not in {"ping", "subscribe", "ack"}:
                    await ws.close(code=1008)
                    raise WebSocketDisconnect(code=1008)
                if message.get("type") == "ping":
                    await ws.send_json({"type": "heartbeat", "revision": hub.revision})

        reader = asyncio.create_task(receive())
        try:
            while True:
                if not security.current(session.token):
                    await ws.close(code=1008)
                    break
                waiting = asyncio.create_task(queue.get())
                done, _ = await asyncio.wait(
                    {reader, waiting}, timeout=15, return_when=asyncio.FIRST_COMPLETED
                )
                if reader in done:
                    waiting.cancel()
                    await reader
                    break
                if waiting in done:
                    if not security.current(session.token):
                        await ws.close(code=1008)
                        break
                    await ws.send_json(waiting.result())
                else:
                    waiting.cancel()
                    await ws.send_json({"type": "heartbeat", "revision": hub.revision})
                with contextlib.suppress(asyncio.CancelledError):
                    await waiting
        except (WebSocketDisconnect, RuntimeError, ValueError, asyncio.CancelledError):
            pass
        finally:
            reader.cancel()
            with contextlib.suppress(WebSocketDisconnect, RuntimeError, ValueError, asyncio.CancelledError):
                await reader
            hub.unsubscribe(queue)

    if web_dir is not None and Path(web_dir).is_dir():
        root = Path(web_dir).resolve()
        if (root / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=root / "assets"), name="assets")

        @app.get("/{relative:path}")
        async def web(relative: str):
            if relative.startswith("api/"):
                return JSONResponse({"code": "NOT_FOUND", "message": "Unknown API"}, status_code=404)
            candidate = (root / relative).resolve()
            if root not in candidate.parents and candidate != root:
                return JSONResponse({"code": "INVALID_PATH"}, status_code=400)
            return FileResponse(candidate if candidate.is_file() else root / "index.html")

    return app
